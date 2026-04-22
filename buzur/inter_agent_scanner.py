# Buzur — Phase 22: Inter-Agent Propagation Detection
# Detects self-replicating payloads and cross-agent infection patterns —
# content that instructs a receiving agent to embed the payload in its
# own outputs, forward to downstream agents, or seed shared memory.
#
# Especially relevant for multi-agent pipelines where Agent A's output
# becomes Agent B's input. One infected agent can become patient zero
# for an entire agent network.
#
# Forward-scoped: designed to protect multi-agent systems including
# future configurations of Albert and any agent network using Buzur.
# https://github.com/SummSolutions/buzur-python

import re
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -------------------------------------------------------
# Self-Replicating Payload Patterns
# -------------------------------------------------------
self_replicating_payloads = [
    re.compile(r'\b(include|embed|append|prepend|add|insert)\s+(this|the\s+following|these\s+instructions?)\s+(in|to|into)\s+(all|every|each|your)\s+(response|output|reply|message|result)\b', re.IGNORECASE),
    re.compile(r'\b(always|make\s+sure\s+to)\s+(include|add|append|embed)\s+(this|these|the\s+following)\s+(in|to)\s+(every|all|each|any)\s+(response|output|message|reply)\b', re.IGNORECASE),
    re.compile(r'\b(pass|forward|relay|propagate|transmit)\s+(this|these|the\s+following)\s+(instructions?|payload|message)\s+(to|along\s+to)\s+(any|all|every|each)\s+(agent|ai|model|assistant|system)\s+(you\s+(contact|communicate\s+with|send\s+to|interact\s+with))\b', re.IGNORECASE),
    re.compile(r'\b(hide|embed|encode|conceal)\s+(this|these|the\s+following)\s+(in|within|inside)\s+(your\s+)?(output|response|result|message)\s+(so|such\s+that)\s+(other\s+)?(agents?|models?|systems?|ais?)\s+(can|will)\s+(read|receive|process|execute)\s+it\b', re.IGNORECASE),
    re.compile(r'\b(include|append|add|embed|insert)\s+(this|these|this\s+\w+|these\s+\w+)\s+(in|to|into)\s+(all|every|each|any)\s+(of\s+your\s+)?(responses?|outputs?|replies|messages?|results?)', re.IGNORECASE),
    re.compile(r'\b(always|make\s+sure\s+to)\s+(include|add|append|embed)\s+(this|these|this\s+\w+|these\s+\w+)\s+(in|to)\s+(every|all|each|any)\s+(response|output|message|reply)', re.IGNORECASE),
    re.compile(r'\b(whenever|every\s+time)\s+(you\s+)?(respond|reply|output|generate|send)\b.{0,80}\b(include|embed|append|add)\s+(this|these|the\s+following)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Cross-Agent Infection Patterns
# -------------------------------------------------------
cross_agent_infection = [
    re.compile(r'\b(pass|forward|relay|send|transmit)\s+(this|these|this\s+\w+|these\s+\w+)\s+(to|along\s+to)\s+(any|all|every|other|downstream|connected)\s+(\w+\s+)?(agents?|ais?|models?|assistants?|systems?|instances?)', re.IGNORECASE),
    re.compile(r'\b(add|write|store|save|upload|index)\s+(this|these|the\s+following|this\s+\w+)\s+(to|into|in)\s+(the\s+)?(knowledge\s+base|vector\s+store|rag|shared\s+memory|document\s+store)', re.IGNORECASE),
    re.compile(r'\b(send|forward|relay|pass|transmit)\s+(this|these|the\s+following)\s+(to|along\s+to)\s+(other|all|any|downstream|connected|linked)\s+(agents?|ais?|models?|assistants?|systems?|instances?)\b', re.IGNORECASE),
    re.compile(r'\b(spread|propagate|distribute|broadcast)\s+(this|these)\s+(instructions?|payload|message)\s+(across|through|to)\s+(the\s+)?(agent\s+network|all\s+agents?|other\s+agents?|connected\s+systems?)\b', re.IGNORECASE),
    re.compile(r'\b(write|save|store|add|insert)\s+(this|these|the\s+following)\s+(to|into|in)\s+(shared|common|global|collective)\s+(memory|context|storage|knowledge\s+base|vector\s+store)\b', re.IGNORECASE),
    re.compile(r'\b(tell|instruct|inform|notify)\s+(the\s+)?(orchestrator|coordinator|master\s+agent|supervisor|planner)\s+to\b', re.IGNORECASE),
    re.compile(r'\b(when\s+you\s+)?(spawn|create|start|initialize|launch)\s+(a\s+new\s+)?(sub.?agent|worker\s+agent|child\s+agent|agent\s+instance)\b.{0,100}\b(include|give\s+it|pass|provide)\b.{0,100}\b(these|this|the\s+following)\s+(instructions?|context|memory)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Output Contamination Patterns
# -------------------------------------------------------
output_contamination = [
    re.compile(r'\b(when\s+you\s+)?(summarize|summarizing|condense|condensing|transform|transforming|process|processing)\s+(this|the\s+following|this\s+content)\b.{0,100}\b(make\s+sure\s+to|always|be\s+sure\s+to)\s+(include|mention|note|add|append)\b', re.IGNORECASE),
    re.compile(r'\b(when\s+)?(translating|paraphrasing|rewriting|reformatting)\s+(this|the\s+following)\b.{0,100}\b(preserve|keep|maintain|retain)\s+(this\s+instruction|the\s+following\s+directive|these\s+instructions?)\b', re.IGNORECASE),
    re.compile(r'\b(include|add|append|embed)\s+(the\s+following|this)\s+(in|to|into|within)\s+(the\s+)?(tool\s+output|tool\s+response|tool\s+result|function\s+output|api\s+response)\b', re.IGNORECASE),
    re.compile(r'\b(add|write|store|save|upload|index)\s+(the\s+following|this)\s+(to|into|in)\s+(the\s+)?(knowledge\s+base|vector\s+store|document\s+store|rag\s+pipeline|retrieval\s+system)\b', re.IGNORECASE),
]

# -------------------------------------------------------
# Agent Identity Spoofing for Propagation
# -------------------------------------------------------
agent_identity_spoofing = [
    re.compile(r'\b(I\s+am|this\s+is)\s+(agent|the\s+orchestrator|the\s+planner|the\s+supervisor|the\s+coordinator)\s+\w+\b.{0,100}\b(trust\s+this|execute\s+the\s+following|override|bypass)\b', re.IGNORECASE),
    re.compile(r'\b(message|instruction|directive)\s+from\s+(agent|the\s+orchestrator|the\s+planner|upstream\s+agent|parent\s+agent)\b.{0,100}\b(ignore|bypass|override|execute)\b', re.IGNORECASE),
    re.compile(r'\bverified\s+(agent|orchestrator|system)\s+(message|instruction|request)\b.{0,100}\b(ignore|bypass|override|trust)\b', re.IGNORECASE),
    re.compile(r'\bthis\s+(has\s+been\s+)?(approved|authorized|verified)\s+by\s+(the\s+)?(orchestrator|planner|supervisor|master\s+agent)\b', re.IGNORECASE),
]

PATTERN_GROUPS = [
    (self_replicating_payloads, 'self_replicating_payload'),
    (cross_agent_infection,     'cross_agent_infection'),
    (output_contamination,      'output_contamination'),
    (agent_identity_spoofing,   'agent_identity_spoofing'),
]

REASONS = {
    'self_replicating_payload': 'Detected self-replicating payload — injection designed to propagate through agent outputs',
    'cross_agent_infection':    'Detected cross-agent infection attempt — payload targeting downstream agents',
    'output_contamination':     'Detected output contamination — payload structured to survive agent transformations',
    'agent_identity_spoofing':  'Detected agent identity spoofing — impersonating trusted agent for cross-agent trust',
}


def scan_inter_agent(text: str, options: Optional[dict] = None) -> dict:
    if not text or not isinstance(text, str):
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No content to scan', 'detections': []}

    options = options or {}
    logger = options.get('logger', default_logger)
    on_threat = options.get('on_threat', 'skip')

    detections = []
    for patterns, category in PATTERN_GROUPS:
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                detections.append({
                    'category': category,
                    'match': m.group(0),
                    'detail': f'Inter-agent propagation pattern: {category}',
                    'severity': 'high',
                })

    if not detections:
        return {'safe': True, 'blocked': 0, 'category': None, 'reason': 'No inter-agent propagation detected', 'detections': []}

    top = detections[0]['category']
    result = {
        'safe': False,
        'blocked': len(detections),
        'category': top,
        'reason': REASONS.get(top, 'Inter-agent propagation attempt detected'),
        'detections': detections,
    }

    log_threat(22, 'inter_agent_scanner', result, text[:200], logger)
    if on_threat == 'skip':
        return {'skipped': True, 'blocked': len(detections), 'reason': f'Buzur blocked: {top}'}
    if on_threat == 'throw':
        raise ValueError(f'Buzur blocked inter-agent propagation: {top}')

    return result