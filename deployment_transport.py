"""Explicit deployment origins and browser-cookie policy.

HTTPS remains the default, including when an HTTPS proxy forwards plain HTTP.
Local HTTP must be selected by the operator and use a private IPv4 address.
"""
import ipaddress
import re
from urllib.parse import urlsplit


MODES = ("https", "lan-http")
LAN_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))


def private_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        return False
    return any(address in network for network in LAN_NETWORKS)


def validate_origin(value, mode="https"):
    """Return a canonical origin without inferring transport from a request."""
    if mode not in MODES:
        raise ValueError("KEEP_TRANSPORT_MODE must be https or lan-http")
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("KEEP_URL must be an origin without a path")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("KEEP_URL contains an invalid address or port") from error
    scheme = "http" if mode == "lan-http" else "https"
    if (parsed.scheme.lower() != scheme or not parsed.hostname or
            parsed.username is not None or parsed.password is not None or
            parsed.query or parsed.fragment or parsed.path not in ("", "/") or
            any(char.isspace() or ord(char) < 32 for char in value) or
            not re.fullmatch(r"[A-Za-z0-9.:-]+", parsed.hostname)):
        raise ValueError(f"KEEP_URL must contain only an {scheme.upper()} origin")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("KEEP_URL contains an invalid port")
    if mode == "lan-http" and not private_ipv4(parsed.hostname):
        raise ValueError("Local HTTP requires a private or loopback IPv4 address")
    return f"{scheme}://{parsed.netloc}".rstrip("/")


def cookie_policy(mode="https", origin=""):
    """Reject an unsafe deployment before issuing session cookies."""
    if mode not in MODES:
        raise ValueError("KEEP_TRANSPORT_MODE must be https or lan-http")
    # Legacy installations can start without a URL and configure it later.
    # Local HTTP cannot enable non-Secure cookies without a validated origin.
    if origin or mode == "lan-http":
        validate_origin(origin, mode)
    return mode == "https"
