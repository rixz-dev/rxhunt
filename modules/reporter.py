"""
Reporter
Rich-formatted terminal output and JSON/TXT report generation.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.rule import Rule
    from rich import box
    from rich.columns import Columns
    from rich.padding import Padding
except ImportError:
    print("[!] Missing rich. Run: pip install rich --break-system-packages")
    import sys; sys.exit(1)

console = Console(highlight=False)

# ── Severity Styling ─────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "dim cyan",
}

SEVERITY_BADGE = {
    "CRITICAL": "[bold red on #1a0000] CRITICAL [/bold red on #1a0000]",
    "HIGH":     "[bold red] HIGH     [/bold red]",
    "MEDIUM":   "[bold yellow] MEDIUM   [/bold yellow]",
    "LOW":      "[dim cyan] LOW      [/dim cyan]",
}

INDICATION_STYLE = {
    "CONFIRMED_SSRF":        "bold red",
    "POTENTIAL_SSRF":        "yellow",
    "TIMEOUT_BLIND_POSSIBLE":"cyan",
    "ERROR_BLIND_POSSIBLE":  "dim yellow",
}

BANNER = r"""
 ██████╗ ██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██╔══██╗╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ██████╔╝ ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   
 ██╔══██╗ ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   
 ██║  ██║██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝  
"""


class Reporter:
    def __init__(self):
        self.console = console

    def print_banner(self) -> None:
        t = Text()
        t.append(BANNER, style="bold cyan")
        t.append("  JS Secret Harvester  +  SSRF Probe Chain\n", style="bold white")
        t.append(f"  v1.0.0  |  r¡xzXsploit | reiz_riz ", style="dim")
        self.console.print(Panel(t, border_style="cyan", padding=(0, 2)))

    def print_section(self, title: str) -> None:
        self.console.print()
        self.console.rule(f"[bold cyan]{title}[/bold cyan]", style="dim cyan")

    def _redact(self, value: str, show: int = 8) -> str:
        """Partially redact a secret value for safe display."""
        if len(value) <= show * 2:
            return value[:show] + "..." if len(value) > show else value
        return value[:show] + "..." + value[-4:]

    # ── JS Harvest Output ────────────────────────────────────────────────

    def print_js_findings(self, findings: List[Dict[str, Any]]) -> None:
        if not findings:
            self.console.print("[dim]  No secrets found in JS files.[/dim]")
            return

        # Group by severity
        grouped: Dict[str, List] = {s: [] for s in SEVERITY_STYLE}
        for f in findings:
            sev = f.get("severity", "LOW")
            if sev in grouped:
                grouped[sev].append(f)
            else:
                grouped["LOW"].append(f)

        total = len(findings)
        crit  = len(grouped["CRITICAL"])
        high  = len(grouped["HIGH"])

        summary = (
            f"[bold cyan]Findings: {total}[/bold cyan]  "
            f"[red]{crit} CRITICAL[/red]  "
            f"[yellow]{high} HIGH[/yellow]  "
            f"[dim]{len(grouped['MEDIUM'])} MEDIUM  {len(grouped['LOW'])} LOW[/dim]"
        )
        self.console.print(f"\n  {summary}\n")

        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            items = grouped[severity]
            if not items:
                continue

            style = SEVERITY_STYLE[severity]
            badge = SEVERITY_BADGE[severity]
            self.console.print(f"  {badge}  [dim]({len(items)} findings)[/dim]")

            tbl = Table(
                box=box.SIMPLE_HEAD,
                border_style="dim",
                show_header=True,
                header_style="dim",
                padding=(0, 1),
                expand=True,
            )
            tbl.add_column("Type",        style="dim", width=26, no_wrap=True)
            tbl.add_column("Description", width=22, no_wrap=True)
            tbl.add_column("Value",       width=36)
            tbl.add_column("Source File", style="dim", width=22, no_wrap=True)

            for item in items:
                val_display = self._redact(item["value"])
                src = item["source"].split("/")[-1] or item["source"]
                if len(src) > 22:
                    src = "..." + src[-19:]

                tbl.add_row(
                    item["type"],
                    item.get("description", ""),
                    f"[{style}]{val_display}[/{style}]",
                    src,
                )

            self.console.print(Padding(tbl, (0, 2)))

    def print_js_file_list(self, js_files: List[str]) -> None:
        self.console.print(f"\n  [bold cyan]JS Files Discovered:[/bold cyan] {len(js_files)}")
        for f in js_files[:10]:
            self.console.print(f"  [dim]→[/dim] {f}")
        if len(js_files) > 10:
            self.console.print(f"  [dim]... and {len(js_files) - 10} more[/dim]")

    # ── SSRF Probe Output ────────────────────────────────────────────────

    def print_ssrf_results(self, results: List[Dict[str, Any]]) -> None:
        interesting = [
            r for r in results
            if isinstance(r, dict)
            and r.get("indication") not in ("none", "error", None)
            and "__note__" not in r
        ]

        if not interesting:
            self.console.print("[dim]  No SSRF indicators detected.[/dim]")
            return

        confirmed = [r for r in interesting if r.get("indication") == "CONFIRMED_SSRF"]
        potential = [r for r in interesting if r.get("indication") == "POTENTIAL_SSRF"]
        blind     = [r for r in interesting if "BLIND" in r.get("indication", "") or "TIMEOUT" in r.get("indication", "")]

        summary = (
            f"[bold cyan]Indicators: {len(interesting)}[/bold cyan]  "
            f"[bold red]{len(confirmed)} CONFIRMED[/bold red]  "
            f"[yellow]{len(potential)} POTENTIAL[/yellow]  "
            f"[cyan]{len(blind)} BLIND/TIMEOUT[/cyan]"
        )
        self.console.print(f"\n  {summary}\n")

        tbl = Table(
            box=box.SIMPLE_HEAD,
            border_style="dim",
            show_header=True,
            header_style="dim",
            padding=(0, 1),
            expand=True,
        )
        tbl.add_column("Cloud",      width=10, no_wrap=True)
        tbl.add_column("Technique",  width=14, no_wrap=True)
        tbl.add_column("Payload URL",width=48)
        tbl.add_column("Status",     width=7,  no_wrap=True)
        tbl.add_column("Indication", width=26, no_wrap=True)

        for r in interesting:
            p = r.get("payload", {})
            ind = r.get("indication", "")
            ind_style = INDICATION_STYLE.get(ind, "dim")

            url = p.get("url", "?")
            if len(url) > 48:
                url = url[:45] + "..."

            tbl.add_row(
                p.get("cloud", "?"),
                p.get("technique", "?"),
                url,
                str(r.get("status", "?")),
                f"[{ind_style}]{ind}[/{ind_style}]",
            )

        self.console.print(Padding(tbl, (0, 2)))

        # Show snippet for confirmed findings
        for r in confirmed:
            p = r.get("payload", {})
            snippet = r.get("snippet", "")[:300]
            if snippet:
                self.console.print(Panel(
                    f"[dim]{snippet}[/dim]",
                    title=f"[red]CONFIRMED SSRF — {p.get('cloud', '?').upper()} Response Snippet[/red]",
                    border_style="red",
                    padding=(0, 1),
                ))

    # ── OOB Hits Output ──────────────────────────────────────────────────

    def print_oob_hits(self, hits: List[Dict[str, Any]]) -> None:
        if not hits:
            return

        self.console.print(f"\n  [bold red]OOB Callbacks Received: {len(hits)}[/bold red]\n")
        for hit in hits:
            self.console.print(Panel(
                f"[cyan]From      :[/cyan] {hit['remote_ip']}:{hit['remote_port']}\n"
                f"[cyan]Time      :[/cyan] {hit['timestamp']}\n"
                f"[cyan]Method    :[/cyan] {hit.get('method', '?')}\n"
                f"[cyan]Path      :[/cyan] {hit.get('path', '?')}\n"
                f"[cyan]Raw bytes :[/cyan] {hit.get('size', 0)}\n\n"
                f"[dim]{hit.get('raw_preview', '')[:200]}[/dim]",
                title=f"[bold red]OOB HIT #{hit['id']}[/bold red]",
                border_style="red",
            ))

    # ── Summary ──────────────────────────────────────────────────────────

    def print_scan_summary(
        self,
        target: str,
        js_files: int,
        js_findings: int,
        ssrf_indicators: int,
        oob_hits: int,
        elapsed: float,
    ) -> None:
        self.console.print()
        self.console.rule("[bold cyan]Scan Complete[/bold cyan]", style="dim cyan")
        self.console.print(f"""
  [dim]Target      :[/dim] {target}
  [dim]JS Files    :[/dim] {js_files}
  [dim]JS Secrets  :[/dim] [bold]{'[red]' + str(js_findings) + '[/red]' if js_findings else str(js_findings)}[/bold]
  [dim]SSRF Hits   :[/dim] [bold]{'[red]' + str(ssrf_indicators) + '[/red]' if ssrf_indicators else str(ssrf_indicators)}[/bold]
  [dim]OOB Hits    :[/dim] [bold]{'[red]' + str(oob_hits) + '[/red]' if oob_hits else str(oob_hits)}[/bold]
  [dim]Time        :[/dim] {elapsed:.1f}s
""")

    # ── Report Saving ────────────────────────────────────────────────────

    def save_report(self, data: Dict[str, Any], output_path: str) -> None:
        # FIX: Don't silently overwrite existing reports — append timestamp to filename
        if os.path.exists(output_path):
            base, ext = os.path.splitext(output_path)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"{base}_{ts}{ext}"
            self.console.print(
                f"  [yellow]⚠ Report already exists → saving as {output_path}[/yellow]"
            )

        report = {
            "tool": "RXHUNT v2.0.0",
            "author": "rixz | ANERS",
            "generated_at": datetime.now().isoformat(),
            **data,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        self.console.print(f"\n  [green]Report saved →[/green] {os.path.abspath(output_path)}")
