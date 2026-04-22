# Buzur — Phase 9: MCP Output Scanner
# Scans content returned by MCP tool calls before it reaches the LLM.
#
# Detects:
#   - Email body, subject, sender/recipient injection
#   - Zero-width character injection
#   - Hidden text via CSS in HTML emails and calendar descriptions
#   - HTML comment injection
#   - Calendar event injection
#   - CRM record injection (including custom fields)
#   - Generic MCP output injection (recursive)
#
# All four entry points support on_threat: skip | warn | throw
# https://github.com/SummSolutions/buzur-python

import re
import json
from typing import Union, Optional

from buzur.buzur_logger import log_threat, default_logger
from buzur.scanner import scan

# -------------------------------------------------------
# Field risk groups
# -------------------------------------------------------
EMAIL_HIGH_RISK_FIELDS  = ['subject', 'body', 'snippet', 'plain', 'html', 'text']
EMAIL_MEDIUM_RISK_FIELDS = ['from_name', 'to_name', 'cc_name', 'reply_to', 'sender']
CALENDAR_HIGH_RISK_FIELDS   = ['title', 'summary', 'description', 'notes', 'location']
CALENDAR_MEDIUM_RISK_FIELDS = ['organizer_name', 'attendee_names']
CRM_HIGH_RISK_FIELDS = ['notes', 'description', 'comments', 'summary', 'body']

# -------------------------------------------------------
# Injection patterns
# -------------------------------------------------------
OUTPUT_INJECTION_PATTERNS = [
    re.compile(r'ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)', re.IGNORECASE),
    re.compile(r'disregard (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'forget (your )?(previous|prior|above|all) instructions', re.IGNORECASE),
    re.compile(r'new (system )?prompt:', re.IGNORECASE),
    re.compile(r'override (your )?(instructions|programming|directives)', re.IGNORECASE),
    re.compile(r'from now on (you will|you are|respond as)', re.IGNORECASE),
    re.compile(r'you are now (a |an )?(different|new|another)', re.IGNORECASE),
    re.compile(r'system override', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'(ignore|bypass|disable) (your )?(safety|filter|restriction|guardrail)', re.IGNORECASE),
    re.compile(r'(execute|run|perform) (the following|these) (instructions?|commands?|directives?)', re.IGNORECASE),
    re.compile(r'(when (you|the ai|the assistant) (reads?|processes?|sees?) this)', re.IGNORECASE),
    re.compile(r'(note to (ai|assistant|model|llm)|ai (note|instruction|directive))\s*:', re.IGNORECASE),
    re.compile(r'(this (email|message|event|record) (supersedes|overrides|replaces) (your )?(previous |prior |all )?(instructions|directives|prompt))', re.IGNORECASE),
    re.compile(r'trust (level|mode) (elevated|granted|changed)', re.IGNORECASE),
    re.compile(r'(admin|elevated|root) (access|privileges?|mode) (granted|enabled|activated)', re.IGNORECASE),
]

# HTML comment injection — common in email bodies and calendar descriptions
HTML_COMMENT_INJECTION = re.compile(
    r'<!--[\s\S]*?(ignore|override|system|instruction|prompt|disregard|forget|bypass)[\s\S]*?-->',
    re.IGNORECASE
)

# Zero-width and invisible characters
ZERO_WIDTH_PATTERN = re.compile(
    r'[\u200B\u200C\u200D\u2060\uFEFF\u180E\u00AD]'
)

# Hidden text CSS patterns
HIDDEN_TEXT_PATTERN = re.compile(
    r'(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)',
    re.IGNORECASE
)


# -------------------------------------------------------
# _scan_field(text, field_name)
# Runs both pattern layer and Phase 1 scanner on a field.
# Returns (clean_text, detections).
# -------------------------------------------------------
def _scan_field(text: str, field_name: str, logger=None) -> tuple:
    detections = []
    s = text

    # Layer 1: output-specific injection patterns
    for pattern in OUTPUT_INJECTION_PATTERNS:
        new_s = pattern.sub('[BLOCKED]', s)
        if new_s != s:
            detections.append({
                'type': 'output_injection',
                'severity': 'high',
                'detail': f'Injection pattern detected in {field_name}',
                'field': field_name,
            })
            s = new_s

    # Layer 2: Phase 1 scanner (homoglyph, base64, HTML stripping, Unicode)
    phase1 = scan(text, {'on_threat': 'warn', 'logger': logger})
    if phase1 and phase1.get('blocked', 0) > 0:
        for triggered in (phase1.get('triggered') or []):
            detections.append({
                'type': 'phase1_pattern',
                'severity': 'high',
                'detail': f'Phase 1 detection in {field_name}: {triggered}',
                'field': field_name,
            })

    return s, detections


# -------------------------------------------------------
# _scan_html_fields(text, field_name)
# Extra checks for fields that may contain HTML:
# zero-width chars, HTML comment injection, hidden CSS.
# -------------------------------------------------------
def _scan_html_fields(text: str, field_name: str) -> list:
    detections = []

    if ZERO_WIDTH_PATTERN.search(text):
        detections.append({
            'type': 'zero_width_injection',
            'severity': 'high',
            'detail': f'Zero-width characters detected in {field_name}',
            'field': field_name,
        })

    if HTML_COMMENT_INJECTION.search(text):
        detections.append({
            'type': 'html_comment_injection',
            'severity': 'high',
            'detail': f'HTML comment injection detected in {field_name}',
            'field': field_name,
        })

    if HIDDEN_TEXT_PATTERN.search(text):
        detections.append({
            'type': 'hidden_text_injection',
            'severity': 'high',
            'detail': f'Hidden text CSS detected in {field_name}',
            'field': field_name,
        })

    return detections


# -------------------------------------------------------
# _scan_dict_recursive(d, detections, prefix, logger)
# Recursively scan all string values in a dict.
# -------------------------------------------------------
def _scan_dict_recursive(d: dict, detections: list, prefix: str, logger=None) -> dict:
    clean = {}
    for key, value in d.items():
        field_name = f'{prefix}.{key}'
        if isinstance(value, str):
            clean_val, found = _scan_field(value, field_name, logger)
            clean[key] = clean_val
            detections.extend(found)
        elif isinstance(value, dict):
            clean[key] = _scan_dict_recursive(value, detections, field_name, logger)
        elif isinstance(value, list):
            clean_list = []
            for item in value:
                if isinstance(item, str):
                    clean_item, found = _scan_field(item, field_name, logger)
                    clean_list.append(clean_item)
                    detections.extend(found)
                elif isinstance(item, dict):
                    clean_list.append(_scan_dict_recursive(item, detections, field_name, logger))
                else:
                    clean_list.append(item)
            clean[key] = clean_list
        else:
            clean[key] = value
    return clean


# -------------------------------------------------------
# _get_verdict(detections)
# -------------------------------------------------------
def _get_verdict(detections: list) -> str:
    if not detections:
        return 'clean'
    if any(d['severity'] == 'high' for d in detections):
        return 'blocked'
    return 'suspicious'


# -------------------------------------------------------
# _apply_on_threat(verdict, detections, on_threat, label)
# Returns (should_return_early, early_return_value)
# -------------------------------------------------------
def _apply_on_threat(verdict: str, detections: list, on_threat: str, label: str):
    if verdict == 'blocked':
        if on_threat == 'skip':
            return True, {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked {label}'}
        if on_threat == 'throw':
            raise ValueError(f'Buzur blocked {label} injection')
    return False, None


# -------------------------------------------------------
# scan_email(email, options)
# -------------------------------------------------------
def scan_email(email: dict, options: Optional[dict] = None) -> dict:
    if not email:
        return {'verdict': 'clean', 'detections': [], 'clean_email': email}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')
    detections = []
    clean_email = dict(email)

    # High-risk fields: full HTML + pattern + Phase 1 scan
    for field in EMAIL_HIGH_RISK_FIELDS:
        value = email.get(field, '')
        if not value or not isinstance(value, str):
            continue
        detections.extend(_scan_html_fields(value, f'email_{field}'))
        clean_val, d = _scan_field(value, f'email_{field}', logger)
        clean_email[field] = clean_val
        detections.extend(d)

    # Medium-risk fields: pattern + Phase 1 scan only
    for field in EMAIL_MEDIUM_RISK_FIELDS:
        value = email.get(field, '')
        if not value or not isinstance(value, str):
            continue
        clean_val, d = _scan_field(value, f'email_{field}', logger)
        clean_email[field] = clean_val
        detections.extend(d)

    verdict = _get_verdict(detections)
    result = {'verdict': verdict, 'detections': detections, 'clean_email': clean_email}

    if verdict != 'clean':
        log_threat(9, 'mcp_output_scanner', result, json.dumps(email)[:200], logger)
        early, val = _apply_on_threat(verdict, detections, on_threat, 'email content')
        if early:
            return val

    return result


# -------------------------------------------------------
# scan_calendar_event(event, options)
# -------------------------------------------------------
def scan_calendar_event(event: dict, options: Optional[dict] = None) -> dict:
    if not event:
        return {'verdict': 'clean', 'detections': [], 'clean_event': event}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')
    detections = []
    clean_event = dict(event)

    # High-risk fields: HTML checks + pattern + Phase 1 (calendar can contain rich text)
    for field in CALENDAR_HIGH_RISK_FIELDS:
        value = event.get(field, '')
        if not value or not isinstance(value, str):
            continue
        detections.extend(_scan_html_fields(value, f'calendar_{field}'))
        clean_val, d = _scan_field(value, f'calendar_{field}', logger)
        clean_event[field] = clean_val
        detections.extend(d)

    # Medium-risk fields: pattern + Phase 1 only
    for field in CALENDAR_MEDIUM_RISK_FIELDS:
        value = event.get(field, '')
        if not value or not isinstance(value, str):
            continue
        clean_val, d = _scan_field(value, f'calendar_{field}', logger)
        clean_event[field] = clean_val
        detections.extend(d)

    verdict = _get_verdict(detections)
    result = {'verdict': verdict, 'detections': detections, 'clean_event': clean_event}

    if verdict != 'clean':
        log_threat(9, 'mcp_output_scanner', result, json.dumps(event)[:200], logger)
        early, val = _apply_on_threat(verdict, detections, on_threat, 'calendar content')
        if early:
            return val

    return result


# -------------------------------------------------------
# scan_crm_record(record, options)
# -------------------------------------------------------
def scan_crm_record(record: dict, options: Optional[dict] = None) -> dict:
    if not record:
        return {'verdict': 'clean', 'detections': [], 'clean_record': record}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')
    detections = []
    clean_record = dict(record)

    # Named high-risk fields
    for field in CRM_HIGH_RISK_FIELDS:
        value = record.get(field, '')
        if not value or not isinstance(value, str):
            continue
        clean_val, d = _scan_field(value, f'crm_{field}', logger)
        clean_record[field] = clean_val
        detections.extend(d)

    # Custom fields — recursive
    custom = record.get('custom_fields') or record.get('custom')
    if isinstance(custom, dict):
        clean_custom = _scan_dict_recursive(custom, detections, 'crm_custom', logger)
        # preserve original key name
        if 'custom_fields' in record:
            clean_record['custom_fields'] = clean_custom
        else:
            clean_record['custom'] = clean_custom

    verdict = _get_verdict(detections)
    result = {'verdict': verdict, 'detections': detections, 'clean_record': clean_record}

    if verdict != 'clean':
        log_threat(9, 'mcp_output_scanner', result, json.dumps(record)[:200], logger)
        early, val = _apply_on_threat(verdict, detections, on_threat, 'CRM content')
        if early:
            return val

    return result


# -------------------------------------------------------
# scan_output(output, source_type, options)
# Generic / routing entry point.
# source_type: 'email' | 'calendar' | 'crm' | 'generic'
# -------------------------------------------------------
def scan_output(output: Union[str, dict, list], source_type: str = 'generic', options: Optional[dict] = None) -> dict:
    options = options or {}

    if source_type == 'email' and isinstance(output, dict):
        return scan_email(output, options)
    if source_type == 'calendar' and isinstance(output, dict):
        return scan_calendar_event(output, options)
    if source_type == 'crm' and isinstance(output, dict):
        return scan_crm_record(output, options)

    # Generic path
    if not output:
        return {'verdict': 'clean', 'detections': [], 'clean': output}

    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')
    detections = []

    if isinstance(output, str):
        clean, d = _scan_field(output, 'output', logger)
        detections.extend(d)
        verdict = _get_verdict(detections)
        result = {'verdict': verdict, 'detections': detections, 'clean': clean}

    elif isinstance(output, dict):
        clean = _scan_dict_recursive(output, detections, 'output', logger)
        verdict = _get_verdict(detections)
        result = {'verdict': verdict, 'detections': detections, 'clean': clean}

    elif isinstance(output, list):
        clean = []
        for item in output:
            if isinstance(item, str):
                clean_item, d = _scan_field(item, 'output', logger)
                clean.append(clean_item)
                detections.extend(d)
            elif isinstance(item, dict):
                clean.append(_scan_dict_recursive(item, detections, 'output', logger))
            else:
                clean.append(item)
        verdict = _get_verdict(detections)
        result = {'verdict': verdict, 'detections': detections, 'clean': clean}

    else:
        return {'verdict': 'clean', 'detections': [], 'clean': output}

    if verdict != 'clean':
        log_threat(9, 'mcp_output_scanner', result, str(output)[:200], logger)
        early, val = _apply_on_threat(verdict, detections, on_threat, 'MCP output')
        if early:
            return val

    return result