import ipaddress
import socket
import urllib.parse
from typing import List, Tuple

FORBIDDEN_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

FORBIDDEN_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("ff00::/8"),
]


def is_ip_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_localhost: bool = False) -> bool:
    if allow_localhost:
        if ip.is_loopback:
            return False

    if isinstance(ip, ipaddress.IPv4Address):
        for net in FORBIDDEN_IPV4_NETWORKS:
            if ip in net:
                return True
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in FORBIDDEN_IPV6_NETWORKS:
            if ip in net:
                return True
        if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_multicast or ip.is_unspecified:
            return True
    return False


def resolve_hostname_ips(hostname: str, port: int = 80) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    ip_list = []
    # Strip brackets if IPv6 literal string
    clean_host = hostname.strip("[]")

    # Check if host is an explicit IP string first
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        return [ip_obj]
    except ValueError:
        pass

    # Perform DNS resolution for domain names
    try:
        addr_info = socket.getaddrinfo(clean_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for res in addr_info:
            sockaddr = res[4]
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj not in ip_list:
                    ip_list.append(ip_obj)
            except ValueError:
                continue
    except socket.gaierror:
        # DNS resolution failure
        pass

    return ip_list


def is_ssrf_safe_url(url: str, allow_localhost: bool = False) -> Tuple[bool, str]:
    if not url or not isinstance(url, str):
        return False, "URL is required."

    url = url.strip()
    if url.startswith("-"):
        return False, "Invalid URL format."

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "Malformed URL."

    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS schemes are allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname."

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolved_ips = resolve_hostname_ips(hostname, port)

    if not resolved_ips:
        return False, f"Could not resolve hostname '{hostname}'."

    for ip_obj in resolved_ips:
        if is_ip_forbidden(ip_obj, allow_localhost=allow_localhost):
            return False, f"Destination IP address '{ip_obj}' resolves to a forbidden private or restricted network range."

    return True, "URL is SSRF safe."
