import re
from urllib.parse import urlparse


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def normalize_target(target):
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    domain = parsed.hostname

    if not domain:
        raise ValueError("Invalid domain or URL.")

    # Remove trailing dot if present
    domain = domain.rstrip(".")

    if not DOMAIN_PATTERN.match(domain):
        raise ValueError("Invalid domain format.")

    return {
        "original": target,
        "url": target,
        "domain": domain
    }