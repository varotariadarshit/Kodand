import re

_KEY_VALUE = re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+")
_URL_PASSWORD = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'\"<>]{0,64}):[^\s@/'\"<>]{3,}@")
_WHOLE = [re.compile(r"AKIA[0-9A-Z]{16}"), re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")]


def redact(text):
    result = _KEY_VALUE.sub(lambda m: m.group(1) + "=[REDACTED]", text)
    result = _URL_PASSWORD.sub(lambda m: m.group(1) + ":[REDACTED]@", result)
    for p in _WHOLE:
        result = p.sub("[REDACTED SECRET MATERIAL]", result)
    return result
