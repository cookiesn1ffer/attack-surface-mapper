"""
Reporter — Rich terminal output + self-contained HTML report.
"""

from __future__ import annotations

import html
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from .fingerprint import FingerprintResult
    from .portscan import ScanResult

console = Console(force_terminal=False, force_jupyter=False)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)


# ── Terminal helpers ──────────────────────────────────────────────────────────

def _flush() -> None:
    sys.stdout.flush()


def print_banner(domain: str) -> None:
    banner = Text()
    banner.append("Attack Surface Mapper\n", style="bold cyan")
    banner.append(f"  Target: {domain}", style="white")
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))
    _flush()


def print_subdomains(all_subs: list[str], crtsh: list[str], brute: list[str]) -> None:
    table = Table(
        title="[bold cyan]Subdomains Found[/bold cyan]",
        box=box.ROUNDED,
        show_lines=False,
        border_style="cyan",
        title_justify="left",
    )
    table.add_column("Subdomain", style="white", no_wrap=True)
    table.add_column("Source", style="dim")

    crtsh_set = set(crtsh)
    brute_set = set(brute)

    for sub in all_subs:
        sources = []
        if sub in crtsh_set:
            sources.append("[green]crt.sh[/green]")
        if sub in brute_set:
            sources.append("[yellow]brute[/yellow]")
        table.add_row(sub, " + ".join(sources))

    console.print(table)
    console.print(
        f"  [bold green]{len(all_subs)}[/bold green] unique subdomains "
        f"([green]{len(crtsh)}[/green] crt.sh + [yellow]{len(brute)}[/yellow] brute force)\n"
    )
    _flush()


def print_fingerprint(fp: "FingerprintResult") -> None:
    lines: list[str] = []

    if fp.error:
        console.print(f"  [red]ERR[/red] [dim]{fp.host}[/dim] - {fp.error}")
        _flush()
        return

    status_color = "green" if (fp.status_code or 0) < 400 else "red"
    lines.append(f"  [bold]{fp.host}[/bold]  [{status_color}]HTTP {fp.status_code}[/{status_color}]")

    if fp.server:
        lines.append(f"    Server     : [cyan]{fp.server}[/cyan]")
    if fp.powered_by:
        lines.append(f"    Powered-by : [cyan]{fp.powered_by}[/cyan]")
    if fp.redirects_to:
        lines.append(f"    Redirects  : [dim]{fp.redirects_to}[/dim]")
    if fp.technologies:
        tech_str = "  ".join(f"[green]{t}[/green]" for t in fp.technologies)
        lines.append(f"    Tech       : {tech_str}")

    if fp.tls:
        tls = fp.tls
        if tls.error:
            lines.append(f"    TLS        : [red]error — {tls.error}[/red]")
        else:
            color = "red" if tls.expired else ("yellow" if tls.days_remaining < 30 else "green")
            exp = f"[{color}]{tls.days_remaining}d remaining[/{color}]"
            lines.append(f"    TLS        : {exp}  issuer: [dim]{tls.issuer[:60]}[/dim]")
            if tls.san:
                ellipsis = "..." if len(tls.san) > 6 else ""
                lines.append(f"    SANs       : [dim]{', '.join(tls.san[:6])}{ellipsis}[/dim]")

    for line in lines:
        console.print(line)
    console.print()
    _flush()


def print_portscan(result: "ScanResult") -> None:
    if result.error:
        console.print(f"  [red]ERR[/red] Port scan error for [bold]{result.host}[/bold]: {result.error}\n")
        _flush()
        return

    open_ports = result.open_ports
    if not open_ports:
        console.print(f"  [dim]{result.host}[/dim] - no open ports found\n")
        _flush()
        return

    table = Table(
        title=f"[bold]{result.host}[/bold]  [dim]({result.ip})[/dim]  — [green]{len(open_ports)} open ports[/green]",
        box=box.SIMPLE,
        border_style="dim",
        title_justify="left",
        show_header=True,
    )
    table.add_column("Port", style="bold yellow", width=8)
    table.add_column("Proto", style="dim", width=6)
    table.add_column("Service", style="cyan")
    table.add_column("Details", style="white")

    for port in sorted(open_ports, key=lambda p: p.number):
        table.add_row(
            str(port.number),
            port.protocol,
            port.service or "-",
            port.display().replace(port.service, "").strip() or "-",
        )

    console.print(table)
    console.print()
    _flush()


class SimpleProgress:
    """
    Replaces Rich Progress for pipe/GUI mode.
    Emits plain flushed lines instead of in-place bar updates.
    """
    class _Task:
        def __init__(self, description, total):
            self.description = description
            self.total = total
            self.completed = 0

    def __init__(self):
        self._tasks: dict[int, "SimpleProgress._Task"] = {}
        self._next_id = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def add_task(self, description: str, total: int = 100) -> int:
        tid = self._next_id
        self._next_id += 1
        self._tasks[tid] = self._Task(description, total)
        print(f"  >> {description}", flush=True)
        return tid

    def update(self, tid: int, completed: int = 0, total: int | None = None,
               description: str | None = None) -> None:
        task = self._tasks.get(tid)
        if task is None:
            return
        if description:
            task.description = description
        if total is not None:
            task.total = total
        task.completed = completed

    def advance(self, tid: int, step: int = 1) -> None:
        task = self._tasks.get(tid)
        if task:
            task.completed += step
            if task.total and task.completed % max(1, task.total // 10) == 0:
                pct = int(100 * task.completed / task.total)
                print(f"  {task.description}: {pct}%", flush=True)


def make_progress() -> SimpleProgress:
    return SimpleProgress()


# ── HTML report ───────────────────────────────────────────────────────────────

def _h(s: str) -> str:
    return html.escape(str(s))


def _tech_badges(technologies: list[str]) -> str:
    if not technologies:
        return "<span class='none'>—</span>"
    return " ".join(f"<span class='badge'>{_h(t)}</span>" for t in technologies)


def _port_rows(scan: "ScanResult") -> str:
    if scan.error:
        return f"<tr><td colspan='4' class='error'>Error: {_h(scan.error)}</td></tr>"
    if not scan.open_ports:
        return "<tr><td colspan='4' class='none'>No open ports</td></tr>"
    rows = []
    for p in sorted(scan.open_ports, key=lambda x: x.number):
        rows.append(
            f"<tr>"
            f"<td><span class='port'>{p.number}</span></td>"
            f"<td>{_h(p.protocol)}</td>"
            f"<td>{_h(p.service)}</td>"
            f"<td>{_h(p.display().replace(p.service,'').strip()) or '—'}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def generate_html_report(
    domain: str,
    subdomains: dict[str, list[str]],
    fingerprints: list["FingerprintResult"],
    port_scans: list["ScanResult"],
    output_path: Path,
) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fp_map = {f.host: f for f in fingerprints}
    scan_map = {s.host: s for s in port_scans}

    # ── subdomain rows
    sub_rows = []
    for sub in subdomains.get("all", []):
        fp = fp_map.get(sub)
        scan = scan_map.get(sub)

        status = ""
        server = ""
        tech = ""
        tls_info = ""
        ports_str = ""

        if fp and not fp.error:
            sc = fp.status_code or 0
            color = "status-ok" if sc < 400 else "status-err"
            status = f"<span class='{color}'>{sc}</span>"
            server = _h(fp.server)
            tech = _tech_badges(fp.technologies)
            if fp.tls and not fp.tls.error:
                tls_color = "tls-bad" if fp.tls.expired else ("tls-warn" if fp.tls.days_remaining < 30 else "tls-ok")
                tls_info = f"<span class='{tls_color}'>{fp.tls.days_remaining}d</span>"
        elif fp and fp.error:
            status = "<span class='status-err'>error</span>"

        if scan and not scan.error:
            n = len(scan.open_ports)
            ports_str = f"{n} open"
        elif scan and scan.error:
            ports_str = "error"

        sub_rows.append(
            f"<tr>"
            f"<td class='subdomain'>{_h(sub)}</td>"
            f"<td>{status}</td>"
            f"<td>{server}</td>"
            f"<td>{tech}</td>"
            f"<td>{tls_info}</td>"
            f"<td>{ports_str}</td>"
            f"</tr>"
        )

    sub_table = "\n".join(sub_rows)

    # ── port detail sections
    port_sections = []
    for sub in subdomains.get("all", []):
        scan = scan_map.get(sub)
        if not scan or (not scan.open_ports and not scan.error):
            continue
        port_sections.append(f"""
        <div class='host-section'>
          <h3>{_h(sub)} <span class='ip'>({_h(scan.ip)})</span></h3>
          <table class='port-table'>
            <thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Details</th></tr></thead>
            <tbody>{_port_rows(scan)}</tbody>
          </table>
        </div>
        """)
    port_detail_html = "\n".join(port_sections) or "<p class='none'>No port data collected.</p>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Attack Surface Report — {_h(domain)}</title>
  <style>
    :root {{
      --bg: #0f1117;
      --card: #1a1d27;
      --border: #2a2d3a;
      --accent: #00d4ff;
      --green: #00e676;
      --yellow: #ffd740;
      --red: #ff5252;
      --text: #e0e0e0;
      --dim: #888;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
    h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: .25rem; }}
    .meta {{ color: var(--dim); font-size: .85rem; margin-bottom: 2rem; }}
    h2 {{ color: var(--accent); font-size: 1.2rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: .5rem; }}
    h3 {{ color: var(--text); font-size: 1rem; margin-bottom: .5rem; }}
    .ip {{ color: var(--dim); font-size: .85rem; font-weight: normal; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; margin-bottom: 1.5rem; }}
    th {{ background: #22253a; color: var(--accent); font-weight: 600; padding: .6rem 1rem; text-align: left; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; }}
    td {{ padding: .55rem 1rem; border-bottom: 1px solid var(--border); font-size: .875rem; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #20233a; }}
    .subdomain {{ font-family: monospace; color: var(--text); }}
    .status-ok {{ color: var(--green); font-weight: 600; }}
    .status-err {{ color: var(--red); font-weight: 600; }}
    .tls-ok {{ color: var(--green); }}
    .tls-warn {{ color: var(--yellow); }}
    .tls-bad {{ color: var(--red); }}
    .badge {{ background: #2a3a2a; color: var(--green); border-radius: 4px; padding: 1px 6px; font-size: .75rem; display: inline-block; margin: 1px; }}
    .port {{ background: #2a2a3a; color: var(--yellow); border-radius: 4px; padding: 1px 6px; font-family: monospace; }}
    .none {{ color: var(--dim); font-style: italic; }}
    .error {{ color: var(--red); }}
    .host-section {{ margin-bottom: 1.5rem; }}
    .port-table {{ max-width: 700px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; }}
    .stat-num {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
    .stat-label {{ font-size: .8rem; color: var(--dim); margin-top: .25rem; }}
  </style>
</head>
<body>
  <h1>Attack Surface Report</h1>
  <p class='meta'>Target: <strong>{_h(domain)}</strong> · Generated: {_h(ts)}</p>

  <div class='summary-grid'>
    <div class='stat'><div class='stat-num'>{len(subdomains.get('all', []))}</div><div class='stat-label'>Subdomains</div></div>
    <div class='stat'><div class='stat-num'>{len(subdomains.get('crtsh', []))}</div><div class='stat-label'>via crt.sh</div></div>
    <div class='stat'><div class='stat-num'>{len(subdomains.get('brute', []))}</div><div class='stat-label'>via Brute Force</div></div>
    <div class='stat'><div class='stat-num'>{sum(len(s.open_ports) for s in port_scans if not s.error)}</div><div class='stat-label'>Open Ports</div></div>
  </div>

  <h2>Subdomain Overview</h2>
  <table>
    <thead>
      <tr>
        <th>Subdomain</th>
        <th>HTTP Status</th>
        <th>Server</th>
        <th>Technologies</th>
        <th>TLS Expiry</th>
        <th>Ports</th>
      </tr>
    </thead>
    <tbody>{sub_table}</tbody>
  </table>

  <h2>Open Ports Detail</h2>
  {port_detail_html}
</body>
</html>"""

    output_path.write_text(html_content, encoding="utf-8")
