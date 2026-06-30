import ipaddress
import re
from urllib.parse import urlparse

from .exceptions import URLhausUnsafeInputError

def validate_url(url: str) -> None:
    if not url:
        raise URLhausUnsafeInputError("URL cannot be empty.")
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise URLhausUnsafeInputError("Only http and https URLs are allowed.")
        if not parsed.hostname:
            raise URLhausUnsafeInputError("Invalid URL: missing hostname.")
        
        # Check if the hostname is an IP to prevent private IP bypasses
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if not ip.is_global:
                raise URLhausUnsafeInputError(f"URL contains a private, loopback, or reserved IP: {parsed.hostname}")
        except ValueError:
            # It's a domain name. We reject localhost explicitly.
            if parsed.hostname.lower() in ("localhost", "local", "invalid", "test"):
                raise URLhausUnsafeInputError(f"URL contains unsafe hostname: {parsed.hostname}")
    except Exception as e:
        if isinstance(e, URLhausUnsafeInputError):
            raise
        raise URLhausUnsafeInputError(f"Malformed URL: {str(e)}")

def validate_url_id(url_id: str | int) -> None:
    try:
        url_id_int = int(url_id)
        if url_id_int <= 0:
            raise ValueError()
    except ValueError:
        raise URLhausUnsafeInputError("URLhaus ID must be a positive integer.")

def validate_host(host: str) -> None:
    if not host:
        raise URLhausUnsafeInputError("Host cannot be empty.")
    
    if "://" in host or "/" in host or ":" in host or " " in host:
        raise URLhausUnsafeInputError("Host must be a plain domain or IP without schemes, paths, ports, or spaces.")
    
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise URLhausUnsafeInputError(f"Host is a private, loopback, or reserved IP: {host}")
    except ValueError:
        if host.lower() in ("localhost", "local"):
            raise URLhausUnsafeInputError(f"Host is unsafe: {host}")

def validate_payload_hash(hash_value: str) -> str:
    """Returns 'md5' or 'sha256'. Raises URLhausUnsafeInputError if invalid."""
    if not hash_value:
        raise URLhausUnsafeInputError("Hash cannot be empty.")
    
    hash_len = len(hash_value)
    if hash_len == 32 and re.match(r"^[a-fA-F0-9]{32}$", hash_value):
        return "md5_hash"
    elif hash_len == 64 and re.match(r"^[a-fA-F0-9]{64}$", hash_value):
        return "sha256_hash"
    elif hash_len == 40 and re.match(r"^[a-fA-F0-9]{40}$", hash_value):
        raise URLhausUnsafeInputError("SHA1 hashes are not supported by this integration.")
    else:
        raise URLhausUnsafeInputError("Hash must be exactly 32 (MD5) or 64 (SHA256) hexadecimal characters.")

def validate_tag_or_signature(value: str, field_name: str = "Tag") -> None:
    if not value:
        raise URLhausUnsafeInputError(f"{field_name} cannot be empty.")
    if len(value) > 100:
        raise URLhausUnsafeInputError(f"{field_name} is too long (max 100 characters).")
    
    # Allow letters, numbers, spaces, dash, underscore, dot
    if not re.match(r"^[a-zA-Z0-9 _.\-]+$", value):
        raise URLhausUnsafeInputError(f"{field_name} contains unsafe characters.")
