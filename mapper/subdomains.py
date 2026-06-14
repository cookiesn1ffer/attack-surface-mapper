"""
Subdomain enumerator — crt.sh certificate transparency + DNS brute force.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import dns.resolver
import requests

# ── crt.sh ──────────────────────────────────────────────────────────────────

CRT_URL = "https://crt.sh/?q=%.{domain}&output=json"
CRT_TIMEOUT = 15


def _crtsh_query(domain: str) -> list[str]:
    """Pull subdomains from certificate transparency logs via crt.sh."""
    url = CRT_URL.format(domain=domain)
    try:
        resp = requests.get(url, timeout=CRT_TIMEOUT, headers={"Accept": "application/json"})
        resp.raise_for_status()
        entries = resp.json()
    except Exception:
        return []

    seen: set[str] = set()
    results: list[str] = []
    for entry in entries:
        name = entry.get("name_value", "")
        for sub in name.splitlines():
            sub = sub.strip().lower().lstrip("*.")
            if sub.endswith(f".{domain}") or sub == domain:
                if sub not in seen:
                    seen.add(sub)
                    results.append(sub)
    return results


# ── DNS brute force ──────────────────────────────────────────────────────────

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.timeout = 2
_RESOLVER.lifetime = 2


def _resolve(hostname: str) -> str | None:
    """Return the hostname if it resolves, else None."""
    try:
        _RESOLVER.resolve(hostname, "A")
        return hostname
    except Exception:
        return None


def _brute_force(domain: str, wordlist: list[str], workers: int = 50,
                 progress_cb: Callable[[int, int], None] | None = None) -> list[str]:
    """DNS brute force using the provided wordlist."""
    candidates = [f"{word}.{domain}" for word in wordlist]
    found: list[str] = []
    total = len(candidates)
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolve, host): host for host in candidates}
        for fut in as_completed(futures):
            done += 1
            result = fut.result()
            if result:
                found.append(result)
            if progress_cb:
                progress_cb(done, total)

    return found


# ── Public API ───────────────────────────────────────────────────────────────

def enumerate_subdomains(
    domain: str,
    wordlist: list[str],
    workers: int = 50,
    progress_cb: Callable[[str, int, int], None] | None = None,
) -> dict[str, list[str]]:
    """
    Run crt.sh + brute force and return a dict:
      {
        "crtsh": [...],
        "brute": [...],
        "all":   [...],   # deduplicated union
      }
    """
    if progress_cb:
        progress_cb("crtsh", 0, 1)
    crtsh = _crtsh_query(domain)
    if progress_cb:
        progress_cb("crtsh", 1, 1)

    def _brute_cb(done: int, total: int) -> None:
        if progress_cb:
            progress_cb("brute", done, total)

    brute = _brute_force(domain, wordlist, workers=workers, progress_cb=_brute_cb)

    all_subs = sorted(set(crtsh) | set(brute))
    return {"crtsh": sorted(crtsh), "brute": sorted(brute), "all": all_subs}
