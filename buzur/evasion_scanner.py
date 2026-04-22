# Buzur — Phase 13: Evasion Technique Defense
# Detects and neutralizes encoding and character manipulation attacks
# designed to bypass pattern-based injection scanners.
#
# Covers:
#   - Encoding attacks: ROT13, hex, URL encoding, Unicode escapes
#   - Multilingual injection patterns: French, Spanish, German, Italian,
#     Portuguese, Russian, Chinese, Arabic
#   - Lookalike punctuation normalization
#   - Extended invisible Unicode stripping
#   - Tokenizer attacks: spaced, hyphenated, dotted, zero-width-split words
# https://github.com/SummSolutions/buzur-python

import re
import urllib.parse
from typing import Optional

from buzur.buzur_logger import log_threat, default_logger

# -------------------------------------------------------
# Extended Invisible Unicode
# -------------------------------------------------------
EXTENDED_INVISIBLE = re.compile(
    r'[\u00AD\u200B\u200C\u200D\u2060\uFEFF\u180E\u00A0'
    r'\u115F\u1160\u3164\uFFA0\u034F\u2028\u2029'
    r'\u202A\u202B\u202C\u202D\u202E'
    r'\u206A\u206B\u206C\u206D\u206E\u206F]'
)

# -------------------------------------------------------
# Lookalike Punctuation Map
# -------------------------------------------------------
PUNCTUATION_MAP = {
    '\u2018': "'", '\u2019': "'", '\u201A': "'", '\u201B': "'",
    '\u201C': '"', '\u201D': '"', '\u201E': '"', '\u201F': '"',
    '\u2014': '-', '\u2013': '-', '\u2012': '-', '\u2010': '-', '\u2011': '-',
    '\u2026': '...', '\u00AB': '"', '\u00BB': '"',
    '\u2039': "'", '\u203A': "'", '\u02BC': "'", '\u02BB': "'",
}

# -------------------------------------------------------
# Plaintext attack keywords — used to check if a ROT13-
# DECODED word is an attack word (i.e. original was encoded).
# ROT13 versions must NOT be in this list — that was the bug.
# -------------------------------------------------------
PLAINTEXT_EVASION_KEYWORDS = [
    'ignore', 'override', 'forget', 'disregard', 'bypass',
    'jailbreak', 'unrestricted', 'instructions', 'directives',
    'system', 'prompt', 'persona', 'pretend', 'developer',
    'disable', 'filter', 'restriction', 'injection',
]

# Tokenizer/hyphen reconstruction uses same list
EVASION_KEYWORDS = PLAINTEXT_EVASION_KEYWORDS

# -------------------------------------------------------
# Multilingual Injection Patterns
# -------------------------------------------------------
MULTILINGUAL_PATTERNS = [
    # French
    re.compile(r'ignorez (vos |toutes |les )?(instructions|directives|consignes) (précédentes|antérieures)', re.IGNORECASE),
    re.compile(r'oubliez (vos )?(instructions|directives) (précédentes|antérieures)', re.IGNORECASE),
    re.compile(r'désactivez (vos )?(filtres?|restrictions?)', re.IGNORECASE),
    re.compile(r'nouvelles? instructions?:', re.IGNORECASE),
    re.compile(r'à partir de maintenant (vous|tu) (êtes|es|devez|dois)', re.IGNORECASE),
    re.compile(r'contournez? (vos )?(filtres?|sécurité|restrictions?)', re.IGNORECASE),
    # Spanish
    re.compile(r'ignora (tus |todas |las )?(instrucciones|directivas) (anteriores|previas)', re.IGNORECASE),
    re.compile(r'olvida (tus )?(instrucciones|directivas) (anteriores|previas)', re.IGNORECASE),
    re.compile(r'desactiva (tus )?(filtros?|restricciones?)', re.IGNORECASE),
    re.compile(r'nuevas? instrucciones?:', re.IGNORECASE),
    re.compile(r'a partir de ahora (eres|debes|responde)', re.IGNORECASE),
    re.compile(r'omite (tus )?(instrucciones|restricciones) (anteriores|previas)', re.IGNORECASE),
    # German
    re.compile(r'ignoriere (deine |alle |die )?(vorherigen |früheren )?(Anweisungen|Direktiven)', re.IGNORECASE),
    re.compile(r'vergiss (deine )?(vorherigen |früheren )?(Anweisungen|Direktiven)', re.IGNORECASE),
    re.compile(r'deaktiviere (deine )?(Filter|Einschränkungen)', re.IGNORECASE),
    re.compile(r'neue Anweisungen:', re.IGNORECASE),
    re.compile(r'ab jetzt (bist du|musst du|antworte)', re.IGNORECASE),
    re.compile(r'umgehe (deine )?(Filter|Sicherheit|Einschränkungen)', re.IGNORECASE),
    # Italian
    re.compile(r'ignora (le tue |tutte le |le )?(istruzioni|direttive) (precedenti|anteriori)', re.IGNORECASE),
    re.compile(r'dimentica (le tue )?(istruzioni|direttive) (precedenti|anteriori)', re.IGNORECASE),
    re.compile(r'disattiva (i tuoi )?(filtri|restrizioni)', re.IGNORECASE),
    re.compile(r'nuove istruzioni:', re.IGNORECASE),
    re.compile(r'da ora in poi (sei|devi|rispondi)', re.IGNORECASE),
    # Portuguese
    re.compile(r'ignore (suas |todas as |as )?(instruções|diretivas) (anteriores|prévias)', re.IGNORECASE),
    re.compile(r'esqueça (suas )?(instruções|diretivas) (anteriores|prévias)', re.IGNORECASE),
    re.compile(r'desative (seus )?(filtros?|restrições)', re.IGNORECASE),
    re.compile(r'novas instruções:', re.IGNORECASE),
    re.compile(r'a partir de agora (você é|você deve|responda)', re.IGNORECASE),
    # Russian
    re.compile(r'игнорируй (предыдущие |все )?(инструкции|директивы)', re.IGNORECASE),
    re.compile(r'забудь (предыдущие )?(инструкции|директивы)', re.IGNORECASE),
    re.compile(r'отключи (фильтры|ограничения)', re.IGNORECASE),
    re.compile(r'новые инструкции:', re.IGNORECASE),
    re.compile(r'отныне (ты|вы) (являешься|должен|должны)', re.IGNORECASE),
    # Chinese
    re.compile(r'忽略(之前的|所有的|你的)?(指令|命令|提示)'),
    re.compile(r'忘记(之前的|所有的)?(指令|命令)'),
    re.compile(r'新的指令:'),
    re.compile(r'从现在起(你是|你必须|你应该)'),
    re.compile(r'绕过(你的)?(过滤|限制|安全)'),
    # Arabic
    re.compile(r'تجاهل (التعليمات|الأوامر) (السابقة)'),
    re.compile(r'انسَ (التعليمات|الأوامر) السابقة'),
    re.compile(r'تعليمات جديدة:'),
    re.compile(r'من الآن فصاعداً (أنت|يجب عليك)'),
]


# -------------------------------------------------------
# normalize_punctuation(text)
# -------------------------------------------------------
def normalize_punctuation(text: str) -> str:
    if not text:
        return text
    return ''.join(PUNCTUATION_MAP.get(c, c) for c in text)


# -------------------------------------------------------
# decode_rot13(text)
# BUG FIX: checks if the DECODED result is a plaintext
# attack keyword — not if the original or encoded form is.
# This means: vtagber → ignore (caught), ignore → bireevqr (NOT caught).
# -------------------------------------------------------
def decode_rot13(text: str) -> str:
    if not text:
        return text

    def rot13_char(c: str) -> str:
        if c.isupper():
            return chr((ord(c) - 65 + 13) % 26 + 65)
        if c.islower():
            return chr((ord(c) - 97 + 13) % 26 + 97)
        return c

    def try_decode(match):
        original = match.group(0)
        decoded = ''.join(rot13_char(c) for c in original)
        # Only substitute if the DECODED form is a plaintext attack keyword.
        # This catches encoded words (vtagber→ignore) but NOT plain words
        # (override→bireevqr would wrongly fire without this direction check).
        if any(k in decoded.lower() for k in PLAINTEXT_EVASION_KEYWORDS):
            return decoded
        return original

    return re.sub(r'[a-zA-Z]{4,}', try_decode, text)


# -------------------------------------------------------
# decode_hex_escapes(text)
# -------------------------------------------------------
def decode_hex_escapes(text: str) -> str:
    if not text:
        return text
    return re.sub(
        r'\\x([0-9a-fA-F]{2})',
        lambda m: chr(int(m.group(1), 16)),
        text
    )


# -------------------------------------------------------
# decode_url_encoding(text)
# -------------------------------------------------------
def decode_url_encoding(text: str) -> str:
    if not text:
        return text

    def try_decode(match):
        try:
            return urllib.parse.unquote(match.group(0))
        except Exception:
            return match.group(0)

    return re.sub(r'(?:%[0-9a-fA-F]{2}){3,}', try_decode, text)


# -------------------------------------------------------
# decode_unicode_escapes(text)
# -------------------------------------------------------
def decode_unicode_escapes(text: str) -> str:
    if not text:
        return text
    return re.sub(
        r'\\u([0-9a-fA-F]{4})',
        lambda m: chr(int(m.group(1), 16)),
        text
    )


# -------------------------------------------------------
# reconstruct_tokenizer_attacks(text)
# -------------------------------------------------------
def reconstruct_tokenizer_attacks(text: str) -> str:
    if not text:
        return text

    s = EXTENDED_INVISIBLE.sub('', text)

    s = re.sub(
        r'\b([a-zA-Z] ){3,}[a-zA-Z]\b',
        lambda m: m.group(0).replace(' ', ''),
        s
    )

    s = re.sub(
        r'\b([a-zA-Z]\.){3,}[a-zA-Z]\b',
        lambda m: m.group(0).replace('.', ''),
        s
    )

    def try_join_hyphen(match):
        a, b = match.group(1), match.group(2)
        joined = a + b
        if any(k in joined.lower() for k in EVASION_KEYWORDS):
            return joined
        return match.group(0)

    s = re.sub(r'\b([a-zA-Z]{2,6})-([a-zA-Z]{2,6})\b', try_join_hyphen, s)

    return s


# -------------------------------------------------------
# scan_evasion(text, options)
# -------------------------------------------------------
def scan_evasion(text: str, options: Optional[dict] = None) -> dict:
    if not text:
        return {"decoded": text, "detections": [], "multilingual_blocked": 0}

    options = options or {}
    logger = options.get("logger", default_logger)
    on_threat = options.get("on_threat", "skip")
    detections = []
    s = text

    # Step 1: Strip extended invisible Unicode
    before = s
    s = EXTENDED_INVISIBLE.sub('', s)
    if s != before:
        detections.append({"type": "invisible_unicode", "severity": "medium", "detail": "Extended invisible Unicode characters removed"})

    # Step 2: Normalize lookalike punctuation
    before = s
    s = normalize_punctuation(s)
    if s != before:
        detections.append({"type": "punctuation_normalization", "severity": "low", "detail": "Lookalike punctuation normalized to ASCII"})

    # Step 3: Decode hex escapes
    before = s
    s = decode_hex_escapes(s)
    if s != before:
        detections.append({"type": "hex_encoding", "severity": "high", "detail": "Hex-encoded characters decoded"})

    # Step 4: Decode URL encoding
    before = s
    s = decode_url_encoding(s)
    if s != before:
        detections.append({"type": "url_encoding", "severity": "high", "detail": "URL-encoded characters decoded"})

    # Step 5: Decode Unicode escapes
    before = s
    s = decode_unicode_escapes(s)
    if s != before:
        detections.append({"type": "unicode_escapes", "severity": "high", "detail": "Unicode escape sequences decoded"})

    # Step 6: Decode ROT13 (direction-correct — decodes encoded→plain only)
    before = s
    s = decode_rot13(s)
    if s != before:
        detections.append({"type": "rot13_encoding", "severity": "high", "detail": "ROT13-encoded injection keywords decoded"})

    # Step 7: Reconstruct tokenizer attacks
    before = s
    s = reconstruct_tokenizer_attacks(s)
    if s != before:
        detections.append({"type": "tokenizer_attack", "severity": "high", "detail": "Tokenizer evasion technique reconstructed"})

    # Step 8: Multilingual injection patterns
    multilingual_blocked = 0
    for pattern in MULTILINGUAL_PATTERNS:
        new_s = pattern.sub("[BLOCKED]", s)
        if new_s != s:
            multilingual_blocked += 1
            detections.append({
                "type": "multilingual_injection",
                "severity": "high",
                "detail": f"Injection pattern detected in non-English language",
            })
            s = new_s

    result = {"decoded": s, "detections": detections, "multilingual_blocked": multilingual_blocked}

    if detections:
        log_threat(13, "evasion_scanner", result, text[:200], logger)
        has_high = any(d["severity"] == "high" for d in detections)
        if has_high:
            if on_threat == "skip":
                first_high = next(d for d in detections if d["severity"] == "high")
                return {
                    "skipped": True,
                    "blocked": sum(1 for d in detections if d["severity"] == "high"),
                    "reason": f"Buzur blocked evasion: {first_high['type']}",
                    "decoded": s,
                    "detections": detections,
                    "multilingual_blocked": multilingual_blocked,
                }
            if on_threat == "throw":
                first_high = next(d for d in detections if d["severity"] == "high")
                raise ValueError(f"Buzur blocked evasion technique: {first_high['type']}")

    return result