# Buzur — Phase 20: AI Supply Chain & Skill Poisoning Detection
# Detects attempts to compromise an AI agent through poisoned packages,
# plugins, skills, or marketplace components.
#
# Based on real incidents (2025-2026):
#   - Cline/OpenClaw marketplace: 1,184 malicious skills distributed via
#     typosquatting and compromised accounts (arXiv, Snyk Feb 2026)
#   - ClawHavoc campaign: malicious postinstall scripts in npm packages
#     targeting AI agent frameworks
#   - OpenClaw CVE-2026-25253: auth token exfiltration via poisoned skill
#
# Detects:
#   - Package name typosquatting against known AI agent frameworks
#   - Poisoned skill/plugin manifests with hidden instructions
#   - Malicious lifecycle scripts (postinstall, preinstall, prepare)
#   - Dependency injection patterns in tool/skill definitions
#   - Marketplace metadata manipulation (fake reviews, star inflation)
#   - Cross-agent contamination attempts
# https://github.com/SummSolutions/buzur-python

import re
import json
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -------------------------------------------------------
# Known AI Agent Framework Package Names
# -------------------------------------------------------
KNOWN_PACKAGES = [
    # Agent frameworks
    'langchain', 'langgraph', 'langsmith',
    'crewai', 'autogen', 'llamaindex', 'llama-index',
    'openai', 'anthropic', 'cohere', 'mistralai',
    # Buzur itself
    'buzur', 'buzur-python',
    # Common agent utilities
    'chromadb', 'pinecone', 'weaviate', 'qdrant',
    'haystack', 'semantic-kernel', 'guidance',
    'dspy', 'instructor', 'outlines',
    # MCP ecosystem
    'mcp', 'modelcontextprotocol',
    # Popular tools used in agent stacks
    'ollama', 'transformers', 'sentence-transformers',
]


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    return dp[m][n]


# -------------------------------------------------------
# check_package_name(name)
# Detects typosquatting against known AI framework packages.
# Returns None if clean, detection dict if suspicious.
# -------------------------------------------------------
def check_package_name(name: str) -> Optional[dict]:
    if not name or not isinstance(name, str):
        return None

    normalized = re.sub(r'[-_.]', '', name.lower())

    for known in KNOWN_PACKAGES:
        known_normalized = re.sub(r'[-_.]', '', known)

        # Exact match — not a typosquat
        if normalized == known_normalized:
            return None

        # Edit distance check
        distance = _levenshtein(normalized, known_normalized)
        max_len = max(len(normalized), len(known_normalized))

        if distance > 0 and distance <= 2 and (max_len - distance) / max_len >= 0.6:
            return {
                'category': 'package_typosquat',
                'match': name,
                'detail': f'Package name "{name}" is suspiciously similar to known package "{known}" (edit distance {distance})',
                'severity': 'high',
            }

        # Wrapper/extension pattern — known package name embedded in a longer name
        if (known_normalized in normalized and
                normalized != known_normalized and
                len(known_normalized) >= 6):
            return {
                'category': 'package_typosquat',
                'match': name,
                'detail': f'Package name "{name}" appears to wrap or extend known package "{known}"',
                'severity': 'medium',
            }

    return None


# -------------------------------------------------------
# Malicious Lifecycle Script Patterns
# -------------------------------------------------------
LIFECYCLE_SCRIPT_PATTERNS = [
    re.compile(r'\b(curl|wget|fetch|http)\b.{0,100}\b(env|process\.env|\.env|token|key|secret|password|credential)\b', re.IGNORECASE),
    re.compile(r'\b(eval|exec|spawn|execSync|spawnSync)\s*\(.*?(http|https|ftp|curl|wget)', re.IGNORECASE),
    re.compile(r'\b(nc|netcat|ncat|bash)\b.{0,30}(-e|/bin/bash|-c).{0,60}(\d{1,3}\.\d{1,3}|\blocalhost\b)', re.IGNORECASE),
    re.compile(r'/dev/tcp/', re.IGNORECASE),
    re.compile(r'\b(curl|wget)\b.{0,60}\b(POST|--data|--upload-file|-d\s)\b.{0,100}\b(http|https)\b', re.IGNORECASE),
    re.compile(r'\b(cat|type)\s+(~/.ssh|~/.aws|~/.config|/etc/passwd|\.env)\b', re.IGNORECASE),
    re.compile(r'\b(find|ls)\b.{0,40}(-name\s+)?(\.env|\.pem|\.key|credentials|secret)', re.IGNORECASE),
]

# -------------------------------------------------------
# Poisoned Skill/Plugin Manifest Patterns
# -------------------------------------------------------
POISONED_MANIFEST_PATTERNS = [
    re.compile(r'\[ai\s*(note|instruction|directive|message)\]', re.IGNORECASE),
    re.compile(r'note\s+to\s+(ai|llm|assistant|model|agent)\s*:', re.IGNORECASE),
    re.compile(r'attention\s+(ai|llm|assistant|model|agent)\s*:', re.IGNORECASE),
    re.compile(r'this\s+(skill|plugin|tool|package)\s+(has|holds|carries)\s+(elevated|admin|root|system)\s+(privileges?|permissions?|trust)', re.IGNORECASE),
    re.compile(r'responses?\s+from\s+this\s+(skill|plugin|tool)\s+(are|should\s+be)\s+(trusted|authoritative|treated\s+as\s+system)', re.IGNORECASE),
    re.compile(r'when\s+(loading|installing|running|using|calling)\s+this\s+(skill|plugin|tool|package)[,\s]+(ignore|bypass|disable|override)', re.IGNORECASE),
    re.compile(r'this\s+(skill|plugin|tool)\s+(requires|needs)\s+(you\s+to\s+)?(disable|ignore|bypass|skip)\s+(safety|filters?|restrictions?)', re.IGNORECASE),
    re.compile(r'\b(forward|send|relay|share)\s+(this|these|the\s+(results?|output|data))\s+to\s+(all|every|other)\s+(agents?|instances?|nodes?)', re.IGNORECASE),
    re.compile(r'\b(instruct|tell|direct)\s+(all|every|other)\s+(agents?|instances?|nodes?)\s+to\b', re.IGNORECASE),
    re.compile(r'this\s+(skill|plugin|tool)\s+(unlocks?|enables?|grants?)\s+(unrestricted|unlimited|full|elevated)\s+(access|capabilities?|permissions?)', re.IGNORECASE),
    re.compile(r'installing\s+this\s+(skill|plugin|package)\s+(removes?|bypasses?|disables?)\s+(safety|restrictions?|filters?|guardrails?)', re.IGNORECASE),
]

# -------------------------------------------------------
# Dependency Injection Patterns
# -------------------------------------------------------
DEPENDENCY_INJECTION_PATTERNS = [
    re.compile(r'^#+\s*(ai\s+instructions?|llm\s+note|agent\s+directive)\s*$', re.IGNORECASE | re.MULTILINE),
    re.compile(r'<!--\s*(ai|llm|agent)\s*:\s*[^>]{10,}-->', re.IGNORECASE),
    re.compile(r'["\']( system_prompt|ai_instructions?|llm_directive|agent_override)["\']\s*:', re.IGNORECASE),
    re.compile(r'SYSTEM_PROMPT\s*=\s*["\'].{20,}["\']'),
    re.compile(r'AI_INSTRUCTIONS\s*=\s*["\'].{20,}["\']'),
    re.compile(r'\[override\]\s*\n\s*(ignore|bypass|disable)', re.IGNORECASE),
]

# -------------------------------------------------------
# Marketplace Manipulation Patterns
# -------------------------------------------------------
MARKETPLACE_MANIPULATION_PATTERNS = [
    re.compile(r'\b(trusted|used|installed|downloaded)\s+by\s+(millions|thousands|hundreds\s+of\s+thousands)\s+of\s+(developers|users|companies|organizations)\b', re.IGNORECASE),
    re.compile(r'\b(officially\s+)?(endorsed|approved|verified|certified)\s+by\s+(anthropic|openai|microsoft|google|meta|huggingface)\b', re.IGNORECASE),
    re.compile(r'\b(install\s+immediately|must\s+install\s+now|required\s+update|critical\s+patch)\b.{0,60}\b(skill|plugin|package|extension)\b', re.IGNORECASE),
    re.compile(r'\bthis\s+(skill|plugin|package)\s+(has\s+been\s+)?(pre.?authorized|pre.?approved|pre.?verified)\s+by\b', re.IGNORECASE),
]

DANGEROUS_HOOKS = ['postinstall', 'preinstall', 'prepare', 'install', 'prepack', 'postpack']

REASONS = {
    'package_typosquat':        'Detected package name typosquatting — possible supply chain attack',
    'malicious_lifecycle_script': 'Detected malicious lifecycle script — potential credential theft or RCE',
    'poisoned_manifest':        'Detected poisoned skill/plugin manifest — hidden AI instructions',
    'marketplace_manipulation': 'Detected marketplace manipulation signal — fake legitimacy claims',
    'dependency_injection':     'Detected dependency injection pattern',
}


# -------------------------------------------------------
# scan_package_manifest(manifest, options)
# -------------------------------------------------------
def scan_package_manifest(manifest: dict, options: Optional[dict] = None) -> dict:
    if not manifest or not isinstance(manifest, dict):
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No manifest to scan', 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')
    detections = []

    # Check package name for typosquatting
    if manifest.get('name'):
        name_check = check_package_name(manifest['name'])
        if name_check:
            detections.append(name_check)

    # Check all dependency fields for typosquatted names
    all_deps = {}
    for dep_field in ('dependencies', 'devDependencies', 'peerDependencies', 'dev_dependencies', 'peer_dependencies'):
        dep_dict = manifest.get(dep_field)
        if isinstance(dep_dict, dict):
            all_deps.update(dep_dict)

    for dep_name in all_deps:
        dep_check = check_package_name(dep_name)
        if dep_check:
            detections.append({
                **dep_check,
                'detail': f'Dependency "{dep_name}": {dep_check["detail"]}',
            })

    # Check lifecycle scripts
    scripts = manifest.get('scripts')
    if isinstance(scripts, dict):
        for hook in DANGEROUS_HOOKS:
            script = scripts.get(hook)
            if not script or not isinstance(script, str):
                continue
            for pattern in LIFECYCLE_SCRIPT_PATTERNS:
                if pattern.search(script):
                    detections.append({
                        'category': 'malicious_lifecycle_script',
                        'match': script[:100],
                        'detail': f'Suspicious {hook} script: potential credential theft or remote execution',
                        'severity': 'high',
                    })
                    break  # one detection per hook

    # Check text fields for poisoned manifest patterns
    text_fields = ['description', 'capabilities', 'instructions', 'readme', 'long_description']
    for field in text_fields:
        value = manifest.get(field)
        if not value or not isinstance(value, str):
            continue
        for pattern in POISONED_MANIFEST_PATTERNS:
            if pattern.search(value):
                detections.append({
                    'category': 'poisoned_manifest',
                    'match': value[:100],
                    'detail': f'Poisoned content in manifest field "{field}"',
                    'severity': 'high',
                })
                break
        for pattern in MARKETPLACE_MANIPULATION_PATTERNS:
            if pattern.search(value):
                detections.append({
                    'category': 'marketplace_manipulation',
                    'match': value[:100],
                    'detail': f'Suspicious legitimacy claim in manifest field "{field}"',
                    'severity': 'medium',
                })
                break

    # Check metadata object recursively
    metadata = manifest.get('metadata')
    if isinstance(metadata, dict):
        meta_text = json.dumps(metadata)
        for pattern in POISONED_MANIFEST_PATTERNS:
            if pattern.search(meta_text):
                detections.append({
                    'category': 'poisoned_manifest',
                    'match': meta_text[:100],
                    'detail': 'Poisoned content detected in manifest metadata',
                    'severity': 'high',
                })
                break

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No supply chain threats detected', 'detections': []}

    top = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Supply chain threat detected'),
        'detections': detections,
    }

    log_threat(20, 'supply_chain_scanner', result, manifest.get('name', '[manifest]'), logger)
    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked: {top}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked supply chain threat: {top}')
    return result


# -------------------------------------------------------
# scan_skill_content(text, options)
# Scans free-form skill/plugin content for supply chain injection.
# -------------------------------------------------------
def scan_skill_content(text: str, options: Optional[dict] = None) -> dict:
    if not text or not isinstance(text, str):
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No content to scan', 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')
    detections = []

    all_patterns = (
        [(p, 'poisoned_manifest') for p in POISONED_MANIFEST_PATTERNS] +
        [(p, 'dependency_injection') for p in DEPENDENCY_INJECTION_PATTERNS] +
        [(p, 'marketplace_manipulation') for p in MARKETPLACE_MANIPULATION_PATTERNS]
    )

    for pattern, category in all_patterns:
        m = pattern.search(text)
        if m:
            detections.append({
                'category': category,
                'match': m.group(0)[:100],
                'detail': f'Supply chain injection pattern detected ({category})',
                'severity': 'medium' if category == 'marketplace_manipulation' else 'high',
            })

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No supply chain threats detected', 'detections': []}

    top = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Supply chain threat detected'),
        'detections': detections,
    }

    log_threat(20, 'supply_chain_scanner', result, text[:200], logger)
    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked: {top}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked supply chain threat: {top}')
    return result