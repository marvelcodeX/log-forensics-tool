"""
geo.py
------
IP geolocation using the free ip-api.com JSON endpoint (no API key needed).
Results are cached in-process to avoid hammering the API.

Returns a GeoInfo dict:
{
    "ip":      str,
    "country": str,
    "region":  str,
    "city":    str,
    "lat":     float,
    "lon":     float,
    "isp":     str,
    "error":   str | None,
}
"""

import urllib.request
import urllib.error
import json
from typing import Optional

_cache: dict[str, dict] = {}

_PRIVATE_RANGES = [
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.0.0.0", "::1",
]


def _is_private(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_RANGES)


def lookup(ip: str, timeout: int = 4) -> dict:
    """
    Look up geolocation for an IP address.
    Private/loopback IPs return a LOCAL entry without a network call.
    """
    if ip in _cache:
        return _cache[ip]

    if _is_private(ip):
        result = {
            "ip": ip, "country": "Local Network", "region": "",
            "city": "", "lat": 0.0, "lon": 0.0, "isp": "Private", "error": None,
        }
        _cache[ip] = result
        return result

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,query"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") == "success":
            result = {
                "ip":      data.get("query", ip),
                "country": data.get("country", "Unknown"),
                "region":  data.get("regionName", ""),
                "city":    data.get("city", ""),
                "lat":     data.get("lat", 0.0),
                "lon":     data.get("lon", 0.0),
                "isp":     data.get("isp", ""),
                "error":   None,
            }
        else:
            result = _error_result(ip, data.get("message", "lookup failed"))

    except Exception as exc:
        result = _error_result(ip, str(exc))

    _cache[ip] = result
    return result


def _error_result(ip: str, msg: str) -> dict:
    return {
        "ip": ip, "country": "Unknown", "region": "", "city": "",
        "lat": 0.0, "lon": 0.0, "isp": "", "error": msg,
    }


def bulk_lookup(ips: list[str]) -> dict[str, dict]:
    """Look up a list of unique IPs. Returns {ip: GeoInfo}."""
    return {ip: lookup(ip) for ip in set(ips)}


def geo_summary(geo: dict) -> str:
    """Human-readable one-liner for a GeoInfo dict."""
    if geo["error"] and geo["country"] == "Unknown":
        return f"{geo['ip']} (lookup failed)"
    parts = [geo["country"]]
    if geo["city"]:
        parts.insert(0, geo["city"])
    if geo["isp"]:
        parts.append(geo["isp"])
    return ", ".join(p for p in parts if p)