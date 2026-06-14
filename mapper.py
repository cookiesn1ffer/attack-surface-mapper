#!/usr/bin/env python3
"""
Attack Surface Mapper — main entry point.

Usage:
    python mapper.py example.com
    python mapper.py example.com --no-ports
    python mapper.py example.com --wordlist /path/to/wordlist.txt
    python mapper.py example.com --workers 100 --output report.html
"""

from __future__ import annotations

import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ── bootstrap path so `mapper` package is importable from project root
sys.path.insert(0, str(Path(__file__).parent))

from mapper.fingerprint import fingerprint_host, FingerprintResult
from mapper.portscan import scan_host, ScanResult
from mapper.reporter import (
    console,
    generate_html_report,
    make_progress,
    print_banner,
    print_fingerprint,
    print_portscan,
    print_subdomains,
)
from mapper.subdomains import enumerate_subdomains

# ── default wordlist bundled with the tool
_DEFAULT_WORDLIST = Path(__file__).parent / "mapper" / "wordlist.txt"


def _load_wordlist(path: Path) -> list[str]:
    words: list[str] = []
    with path.open() as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    return words


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mapper",
        description="Subdomain + Attack Surface Mapper",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--wordlist", "-w",
        type=Path,
        default=_DEFAULT_WORDLIST,
        metavar="FILE",
        help="Wordlist for DNS brute force",
    )
    parser.add_argument(
        "--workers", "-W",
        type=int,
        default=50,
        metavar="N",
        help="Concurrent DNS resolver threads",
    )
    parser.add_argument(
        "--no-brute",
        action="store_true",
        help="Skip DNS brute force (crt.sh only)",
    )
    parser.add_argument(
        "--no-ports",
        action="store_true",
        help="Skip port scanning",
    )
    parser.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="Skip tech fingerprinting",
    )
    parser.add_argument(
        "--ports",
        default="1-65535",
        metavar="RANGE",
        help="Port range to scan (e.g. 1-1024, 80,443,8080)",
    )
    parser.add_argument(
        "--min-rate",
        type=int,
        default=5000,
        metavar="N",
        help="nmap --min-rate (packets/sec)",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        metavar="FILE",
        help="Save HTML report to this path (default: <domain>_report.html)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Only fingerprint/scan the first N subdomains (0 = all)",
    )

    args = parser.parse_args()
    domain = re.sub(r"^https?://", "", args.domain.lower().strip()).rstrip("/")
    output_path = args.output or Path(f"{domain}_report.html")

    # ── Banner
    print_banner(domain)

    # ────────────────────────────────────────────────────────────────────────
    # 1. Subdomain enumeration
    # ────────────────────────────────────────────────────────────────────────
    console.rule("[cyan]Phase 1 · Subdomain Enumeration[/cyan]")

    wordlist = _load_wordlist(args.wordlist) if not args.no_brute else []

    with make_progress() as prog:
        crtsh_task = prog.add_task("crt.sh lookup", total=1)
        brute_task = prog.add_task(
            f"DNS brute force ({len(wordlist)} words)",
            total=max(len(wordlist), 1),
        )

        def _progress(phase: str, done: int, total: int) -> None:
            if phase == "crtsh":
                prog.update(crtsh_task, completed=done, total=max(total, 1))
            else:
                prog.update(brute_task, completed=done, total=max(total, 1))

        subdomains = enumerate_subdomains(
            domain,
            wordlist=wordlist,
            workers=args.workers,
            progress_cb=_progress if not args.no_brute else None,
        )

    print_subdomains(subdomains["all"], subdomains["crtsh"], subdomains["brute"])

    targets = subdomains["all"]
    if args.limit > 0:
        targets = targets[: args.limit]
        console.print(f"  [yellow]Limiting to {args.limit} subdomains[/yellow]\n")

    if not targets:
        console.print("[yellow]No subdomains found. Exiting.[/yellow]")
        sys.exit(0)

    # ────────────────────────────────────────────────────────────────────────
    # 2. Tech fingerprinting
    # ────────────────────────────────────────────────────────────────────────
    fingerprints: list[FingerprintResult] = []

    if not args.no_fingerprint:
        console.rule("[cyan]Phase 2 · Tech Fingerprinting[/cyan]")

        with make_progress() as prog:
            fp_task = prog.add_task("Fingerprinting hosts", total=len(targets))

            def _fp(host: str) -> FingerprintResult:
                result = fingerprint_host(host)
                prog.advance(fp_task)
                return result

            with ThreadPoolExecutor(max_workers=20) as pool:
                futures = {pool.submit(_fp, h): h for h in targets}
                for fut in as_completed(futures):
                    fingerprints.append(fut.result())

        fingerprints.sort(key=lambda f: f.host)
        console.print()
        for fp in fingerprints:
            print_fingerprint(fp)

    # ────────────────────────────────────────────────────────────────────────
    # 3. Port scanning
    # ────────────────────────────────────────────────────────────────────────
    port_scans: list[ScanResult] = []

    if not args.no_ports:
        console.rule("[cyan]Phase 3 · Port Scanning (full 65535)[/cyan]")
        console.print(
            f"  [yellow]Full port scan on {len(targets)} host(s). "
            f"This will take a while (nmap --min-rate {args.min_rate})[/yellow]\n"
        )

        with make_progress() as prog:
            scan_task = prog.add_task("Port scanning", total=len(targets))

            for host in targets:
                prog.update(scan_task, description=f"Scanning {host}")
                result = scan_host(host, ports=args.ports, min_rate=args.min_rate)
                port_scans.append(result)
                prog.advance(scan_task)
                print_portscan(result)

    # ────────────────────────────────────────────────────────────────────────
    # 4. HTML report
    # ────────────────────────────────────────────────────────────────────────
    console.rule("[cyan]Report[/cyan]")
    generate_html_report(domain, subdomains, fingerprints, port_scans, output_path)
    console.print(f"\n  [bold green]Done![/bold green] HTML report saved: [underline]{output_path}[/underline]\n")


if __name__ == "__main__":
    main()
