"""Conservative sharing boundary. Raw evidence stays in the local detail view."""
import dataclasses
import copy
from enum import Enum
import re
from urllib.parse import urlsplit, urlunsplit

REDACTED = '[REDACTED]'
SECRET_KEY = re.compile(r'(?:password|passwd|passphrase|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie|secret|credential|keymaterial)', re.I)
ASSIGNMENT = re.compile(r'''(?ix)(\b(?:pass(?:word|wd|phrase)?|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|authorization|cookie)\b\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&<>]+)''')


def redact_text(text):
    text = str(text)
    # Secret-bearing log lines and authorization headers can contain spaces.
    text = re.sub(r'(?im)(\b(?:Pass|Key Content|محتوى المفتاح)\s*:\s*).*$', r'\1' + REDACTED, text)
    text = re.sub(r'(?im)(\b(?:Authorization|Cookie|Set-Cookie)\s*:\s*).*$', r'\1' + REDACTED, text)
    text = ASSIGNMENT.sub(lambda m: m[1] + REDACTED, text)
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----', REDACTED, text)
    text = re.sub(r'\b(?:AIza[\w-]{20,}|gh[pousr]_[\w]{20,}|sk-[\w-]{20,})\b', REDACTED, text)
    text = re.sub(r'(?i)([a-z]:[\\/]Users[\\/])[^\\/\s"\']+', r'\1[USER]', text)
    # URL values can carry credentials or personal data under arbitrary names.
    def safe_url(match):
        try:
            parsed = urlsplit(match[0])
            host = parsed.netloc.rsplit('@', 1)[-1]
            return urlunsplit((parsed.scheme, host, parsed.path,
                               'redacted' if parsed.query else '', ''))
        except ValueError:
            return '[REDACTED URL]'
    return re.sub(r'https?://[^\s<>"\']+', safe_url, text)


def sanitize(value):
    """Copy a report/prompt without commands, secret fields or raw content.

    This reduces accidental disclosure; it is not a complete DLP classifier.
    """
    if dataclasses.is_dataclass(value):
        value = dataclasses.asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            label = str(key)
            if SECRET_KEY.search(label) or label.lower() in (
                    'cmdline', 'command_line', 'command', 'leaked_data', 'raw_content', 'payload', 'body'):
                result[label] = REDACTED
            elif label.lower() == 'evidence' and isinstance(item, str):
                # Response bodies can contain unlabelled passwords/PII.
                result[label] = '[Raw evidence omitted from shared output; review locally]'
            else:
                result[label] = sanitize(item)
        return result
    if isinstance(value, (list, tuple, set)):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value)


def shareable_copy(value):
    """Keep report dataclass/Enum interfaces while redacting a separate copy."""
    if isinstance(value, Enum):
        return value
    if dataclasses.is_dataclass(value):
        result = copy.copy(value)
        for field in dataclasses.fields(value):
            item = getattr(value, field.name)
            setattr(result, field.name, sanitize({field.name: item})[field.name]
                    if SECRET_KEY.search(field.name) or field.name in ('evidence', 'cmdline', 'command_line')
                    else shareable_copy(item))
        return result
    if isinstance(value, list):
        return [shareable_copy(item) for item in value]
    if isinstance(value, dict):
        return sanitize(value)
    return redact_text(value) if isinstance(value, str) else value
