#!/usr/bin/env python3
"""
RXHUNT v1.0.0
Unified Bug Bounty CLI — JS Secret Harvester + SSRF Probe Chain + JS File Downloader
Author  : r¡xzXsploit | reiz_riz
License : For authorized security testing only.

Usage:
  python rxhunt.py harvest <url>                   [JS secret scan]
  python rxhunt.py probe   <url> --param <param>   [SSRF probe chain]
  python rxhunt.py scan    <url> --param <param>   [full scan]
  python rxhunt.py download <url>                  [JS-referenced file downloader]

Global flags available on all commands:
  --proxy   http://127.0.0.1:8080    Route through Burp/ZAP
  --cookie  "session=abc; csrf=xyz"  Authenticated scans
  --header  "X-Auth: token"          Extra request headers (repeatable)
  --verbose                          Show debug output
"""

import asyncio
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import click
    from rich.console import Console
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn,
        BarColumn, TaskProgressColumn, TimeElapsedColumn,
    )
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
except ImportError:
    print("[!] Missing dependencies. Run: pip install click rich httpx beautifulsoup4 --break-system-packages")
    sys.exit(1)

from modules.js_harvester import JSHarvester
from modules.js_file_downloader import JSFileDownloader
from modules.ssrf_probe import SSRFProbe
from modules.oob_listener import OOBListener
from modules.reporter import Reporter

console = Console(highlight=False)
reporter = Reporter()


# ── Shared option decorators ─────────────────────────────────────────────────

def global_options(f):
    """Decorator that adds proxy/cookie/header/verbose to any command."""
    f = click.option(
        "--verbose", "-v", is_flag=True,
        help="Show debug output (failed fetches, request errors, etc.)"
    )(f)
    f = click.option(
        "--header", "-H", "headers", multiple=True,
        help="Extra request header (repeatable). Format: 'Name: Value'"
    )(f)
    f = click.option(
        "--cookie", default=None,
        help="Cookie string for authenticated scans. Format: 'name=val; name2=val2'"
    )(f)
    f = click.option(
        "--proxy", default=None,
        help="HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp/ZAP)"
    )(f)
    return f


def parse_headers(headers_tuple) -> dict:
    """Parse ('Name: Value', ...) tuple into {Name: Value} dict."""
    result = {}
    for h in headers_tuple:
        name, _, value = h.partition(":")
        if name:
            result[name.strip()] = value.strip()
    return result


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[cyan]{task.description}[/cyan]"),
        BarColumn(bar_width=28, style="dim cyan", complete_style="bold cyan"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def validate_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def load_url_list(path: str) -> list:
    """Load newline-separated URLs from a file. Skips blanks and # comments."""
    if not os.path.isfile(path):
        console.print(f"  [red]Input file not found: {path}[/red]")
        sys.exit(1)
    urls = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(validate_url(line))
    return urls


# ── CLI Root ─────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """RXHUNT — JS Secret Harvester + SSRF Probe Chain + File Downloader"""
    reporter.print_banner()
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ── harvest command ───────────────────────────────────────────────────────────

@cli.command()
@click.argument("url", required=False)
@click.option("--input",      "-i", "input_file", default=None, help="File with URLs (one per line) — multi-target mode")
@click.option("--max-files",  "-m", default=60,   show_default=True, help="Max JS files to scan per target")
@click.option("--timeout",    "-t", default=12,   show_default=True, help="Request timeout (seconds)")
@click.option("--no-entropy",       is_flag=True,                    help="Disable entropy-based detection")
@click.option("--output",     "-o", default=None,                    help="Save JSON report to file")
@global_options
def harvest(url, input_file, max_files, timeout, no_entropy, output, proxy, cookie, headers, verbose):
    """Harvest secrets from JavaScript files on a target URL.

    \b
    Examples:
      python rxhunt.py harvest https://example.com
      python rxhunt.py harvest https://example.com --proxy http://127.0.0.1:8080
      python rxhunt.py harvest https://example.com --cookie "session=abc" --verbose
      python rxhunt.py harvest --input urls.txt --max-files 100 -o report.json
    """
    urls = _resolve_targets(url, input_file)
    extra_headers = parse_headers(headers)
    asyncio.run(_harvest_multi(urls, max_files, timeout, not no_entropy, output, proxy, cookie, extra_headers, verbose))


async def _harvest_multi(urls, max_files, timeout, entropy, output, proxy, cookie, extra_headers, verbose):
    for target_url in urls:
        await _harvest(target_url, max_files, timeout, entropy, output, proxy, cookie, extra_headers, verbose)


async def _harvest(url, max_files, timeout, entropy, output, proxy, cookie, extra_headers, verbose):
    t0 = time.monotonic()

    console.print(f"\n  [bold cyan]Target    :[/bold cyan] {url}")
    console.print(f"  [dim]Max files : {max_files}  |  Timeout : {timeout}s  |  Entropy : {entropy}")
    if proxy:
        console.print(f"  [dim]Proxy     : {proxy}[/dim]")
    console.print()

    harvester = JSHarvester(
        url, timeout=timeout, max_js_files=max_files,
        include_entropy=entropy, verbose=verbose,
        proxy=proxy, extra_headers=extra_headers, cookies=cookie,
    )

    with make_progress() as prog:
        t = prog.add_task("Discovering JS files...", total=None)
        js_files = await harvester.discover_js_files()
        prog.update(t, total=1, completed=1, description=f"Discovered {len(js_files)} JS files")

    reporter.print_js_file_list(js_files)

    if not js_files:
        console.print("\n  [yellow]No JS files discovered. Try --max-files or check the URL.[/yellow]")
        return

    reporter.print_section("JS Secret Harvest")

    with make_progress() as prog:
        task = prog.add_task("Scanning JS files...", total=len(js_files))

        def on_progress(current, total, js_url):
            name = js_url.split("/")[-1][:40] or js_url[:40]
            prog.update(task, completed=current, description=f"Scanning  {name}")

        findings = await harvester.run(progress_callback=on_progress)

    reporter.print_js_findings(findings)

    elapsed = time.monotonic() - t0
    reporter.print_scan_summary(url, len(js_files), len(findings), 0, 0, elapsed)

    if output:
        reporter.save_report({
            "type":           "js_harvest",
            "target":         url,
            "js_files":       js_files,
            "findings_count": len(findings),
            "findings":       findings,
        }, output)


# ── download command ─────────────────────────────────────────────────────────

@cli.command()
@click.argument("url", required=False)
@click.option("--input",      "-i", "input_file",  default=None, help="File with URLs (one per line)")
@click.option("--max-files",  "-m", default=60,    show_default=True, help="Max JS files to crawl for references")
@click.option("--output-dir", "-d", default="rxhunt_downloads", show_default=True, help="Directory to save downloaded files")
@click.option("--no-scan",          is_flag=True,               help="Skip secret scanning on downloaded files")
@click.option("--timeout",    "-t", default=12,    show_default=True, help="Request timeout (seconds)")
@click.option("--output",     "-o", default=None,               help="Save JSON report to file")
@global_options
def download(url, input_file, max_files, output_dir, no_scan, timeout, output, proxy, cookie, headers, verbose):
    """Find and download files referenced in JS (source maps, configs, sensitive paths).

    Parses all discovered JS files for:
      - Source maps (.js.map) — contains original source code
      - Config endpoints (/api/config, /api/settings)
      - Sensitive file references (.env, .sql, .bak, swagger.json, etc.)
      - Known risky paths (/.git/config, /wp-config.php, etc.)

    \b
    Examples:
      python rxhunt.py download https://example.com
      python rxhunt.py download https://example.com -d ./loot --verbose
      python rxhunt.py download https://example.com --proxy http://127.0.0.1:8080
      python rxhunt.py download --input urls.txt -o download_report.json
    """
    urls = _resolve_targets(url, input_file)
    extra_headers = parse_headers(headers)
    asyncio.run(_download_multi(
        urls, max_files, output_dir, not no_scan,
        timeout, output, proxy, cookie, extra_headers, verbose,
    ))


async def _download_multi(urls, max_files, output_dir, scan_downloaded, timeout, output, proxy, cookie, extra_headers, verbose):
    for target_url in urls:
        await _download(target_url, max_files, output_dir, scan_downloaded, timeout, output, proxy, cookie, extra_headers, verbose)


async def _download(url, max_files, output_dir, scan_downloaded, timeout, output, proxy, cookie, extra_headers, verbose):
    t0 = time.monotonic()

    console.print(f"\n  [bold cyan]Target    :[/bold cyan] {url}")
    console.print(f"  [dim]Max JS    : {max_files}  |  Output dir : {output_dir}  |  Scan downloads : {scan_downloaded}[/dim]")
    if proxy:
        console.print(f"  [dim]Proxy     : {proxy}[/dim]")
    console.print()

    # Phase 1: Discover + fetch all JS files (need content to parse refs)
    reporter.print_section("Phase 1/2  JS Discovery")

    harvester = JSHarvester(
        url, timeout=timeout, max_js_files=max_files,
        include_entropy=False, verbose=verbose,
        proxy=proxy, extra_headers=extra_headers, cookies=cookie,
    )

    with make_progress() as prog:
        t = prog.add_task("Discovering JS files...", total=None)
        js_files = await harvester.discover_js_files()
        prog.update(t, total=1, completed=1, description=f"Discovered {len(js_files)} JS files")

    reporter.print_js_file_list(js_files)

    if not js_files:
        console.print("\n  [yellow]No JS files found — nothing to parse for references.[/yellow]")
        return

    # Fetch all JS content (need raw text to parse file refs from)
    js_contents = []
    with make_progress() as prog:
        task = prog.add_task("Fetching JS content...", total=len(js_files))
        completed = 0

        from modules.js_harvester import JSHarvester as _H
        import httpx

        client_opts = harvester.client_opts

        async with httpx.AsyncClient(**client_opts) as client:
            import asyncio as _asyncio
            sem = _asyncio.Semaphore(10)

            async def _fetch(js_url):
                nonlocal completed
                async with sem:
                    content = await harvester.fetch_js(client, js_url)
                    completed += 1
                    prog.update(task, completed=completed)
                    if content:
                        return {"url": js_url, "content": content}
                    return None

            results = await _asyncio.gather(*[_fetch(u) for u in js_files])
            js_contents = [r for r in results if r]

    console.print(f"  [dim]Fetched {len(js_contents)}/{len(js_files)} JS files[/dim]")

    # Phase 2: Parse refs + attempt downloads
    reporter.print_section("Phase 2/2  Referenced File Download")

    downloader = JSFileDownloader(
        url, timeout=timeout, output_dir=output_dir,
        verbose=verbose, proxy=proxy,
        extra_headers=extra_headers, cookies=cookie,
        scan_downloaded=scan_downloaded,
    )

    with make_progress() as prog:
        task = prog.add_task("Downloading referenced files...", total=None)

        def on_dl_progress(current, total, dl_url):
            prog.update(task, total=total, completed=current,
                        description=f"Fetching {dl_url.split('/')[-1][:40]}")

        dl_results = await downloader.run(js_contents, progress_callback=on_dl_progress)

    # ── Print Results ─────────────────────────────────────────────────────
    reporter.print_section("Download Results")

    downloaded = dl_results["downloaded"]
    secrets_in_downloads = dl_results["secrets_in_downloads"]

    if not downloaded:
        console.print("  [yellow]No referenced files returned HTTP 200.[/yellow]")
        console.print(f"  [dim]{dl_results['refs_found']} paths found, all returned non-200 or failed.[/dim]")
    else:
        # Summary table
        table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
            border_style="dim cyan",
            padding=(0, 1),
        )
        table.add_column("Type",    style="dim cyan",  width=22)
        table.add_column("Path",    style="white",     width=50)
        table.add_column("Size",    style="dim",       width=9, justify="right")
        table.add_column("Secrets", style="bold red",  width=8, justify="right")

        for r in downloaded:
            n_secrets = len(r.get("secrets_found", []))
            secret_str = f"[bold red]{n_secrets}[/bold red]" if n_secrets else "[dim]0[/dim]"
            table.add_row(
                r["type"],
                r["path"][:50],
                f"{r['size']:,}B",
                secret_str,
            )
        console.print(table)

        console.print(f"\n  [green]✓[/green] {len(downloaded)} files downloaded to [bold]{os.path.abspath(output_dir)}[/bold]")

        if secrets_in_downloads:
            reporter.print_section("Secrets Found in Downloaded Files")
            reporter.print_js_findings(secrets_in_downloads)

    elapsed = time.monotonic() - t0
    console.print(f"\n  [dim]Refs parsed : {dl_results['refs_found']}  |  Downloaded : {len(downloaded)}  |  Secrets : {len(secrets_in_downloads)}  |  {elapsed:.1f}s[/dim]")

    if output:
        reporter.save_report({
            "type":                 "js_download",
            "target":               url,
            "js_files_scanned":     js_files,
            "refs_found":           dl_results["refs_found"],
            "downloaded_count":     len(downloaded),
            "downloaded":           downloaded,
            "failed_count":         len(dl_results["failed"]),
            "secrets_in_downloads": secrets_in_downloads,
        }, output)


# ── probe command ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("url")
@click.option("--param",        "-p",  required=True,                   help="URL parameter to inject SSRF payload into")
@click.option("--method",       "-m",  default="GET",
              type=click.Choice(["GET", "POST"], case_sensitive=False),  help="HTTP method")
@click.option("--json-post",           is_flag=True,                    help="POST as JSON (application/json) instead of form-encoded")
@click.option("--cloud",        "-c",  multiple=True,
              help="Cloud(s) to test: aws gcp azure alibaba docker kubernetes localhost (default: all)")
@click.option("--oob",                 default=None,                    help="External OOB host (e.g. xyz.burpcollaborator.net)")
@click.option("--listen",              is_flag=True,                    help="Start local OOB listener on LAN IP")
@click.option("--listen-port",         default=8765, show_default=True, help="Local OOB listener port")
@click.option("--no-stop",             is_flag=True,                    help="Don't stop on first confirmed SSRF")
@click.option("--timeout",      "-t",  default=10,   show_default=True, help="Request timeout (seconds)")
@click.option("--output",       "-o",  default=None,                    help="Save JSON report to file")
@global_options
def probe(url, param, method, json_post, cloud, oob, listen, listen_port, no_stop, timeout, output,
          proxy, cookie, headers, verbose):
    """Probe a URL parameter for SSRF using cloud metadata payloads + bypass techniques.

    \b
    Examples:
      python rxhunt.py probe https://example.com/fetch --param url
      python rxhunt.py probe https://example.com/api --param target -m POST --json-post
      python rxhunt.py probe https://example.com/ --param redirect --oob abc.burpcollaborator.net
      python rxhunt.py probe https://example.com/ --param url --proxy http://127.0.0.1:8080
    """
    extra_headers = parse_headers(headers)
    asyncio.run(_probe(
        url, param, method.upper(), list(cloud), oob, listen, listen_port,
        not no_stop, timeout, output, json_post, proxy, cookie, extra_headers, verbose,
    ))


async def _probe(url, param, method, clouds, oob, listen, listen_port,
                 stop_on_confirm, timeout, output, json_post, proxy, cookie, extra_headers, verbose):
    url = validate_url(url)
    t0 = time.monotonic()

    console.print(f"\n  [bold cyan]Target    :[/bold cyan] {url}")
    console.print(f"  [dim]Param     : {param}  |  Method : {method}  |  JSON POST : {json_post}[/dim]")
    console.print(f"  [dim]Clouds    : {', '.join(clouds) if clouds else 'all'}[/dim]")
    if proxy:
        console.print(f"  [dim]Proxy     : {proxy}[/dim]")
    console.print()

    oob_listener = None
    if listen:
        oob_listener = OOBListener(port=listen_port)
        local_ip = oob_listener.get_local_ip()
        try:
            await oob_listener.start()
            oob = oob or f"{local_ip}:{listen_port}"
            console.print(Panel(
                f"[green]Listening on [bold]{local_ip}:{listen_port}[/bold][/green]\n"
                f"[dim]OOB host set to: {oob}[/dim]",
                title="OOB Listener",
                border_style="green",
                padding=(0, 1),
            ))
        except OSError as e:
            console.print(f"  [yellow]OOB listener failed to start: {e}[/yellow]")
            oob_listener = None

    reporter.print_section("SSRF Probe Chain")

    ssrf = SSRFProbe(
        target_url=url, parameter=param,
        oob_host=oob, timeout=timeout,
        clouds=clouds if clouds else None,
        json_post=json_post, verbose=verbose,
        proxy=proxy, extra_headers=extra_headers, cookies=cookie,
    )

    payloads = ssrf.build_all_payloads()
    console.print(f"  [dim]Payloads generated: {len(payloads)}[/dim]\n")

    with make_progress() as prog:
        task = prog.add_task("Running probes...", total=len(payloads))

        def on_progress(current, total, payload_url):
            short = payload_url[:45] + "..." if len(payload_url) > 45 else payload_url
            prog.update(task, completed=current, description=f"Probing  {short}")

        results = await ssrf.run(
            method=method,
            progress_callback=on_progress,
            stop_on_confirm=stop_on_confirm,
        )

    reporter.print_ssrf_results(results)

    hits = []
    if oob_listener:
        await asyncio.sleep(2)
        hits = oob_listener.get_hits()
        reporter.print_oob_hits(hits)
        await oob_listener.stop()

    interesting = [
        r for r in results
        if isinstance(r, dict)
        and r.get("indication") not in ("none", "error", None)
        and "__note__" not in r
    ]

    elapsed = time.monotonic() - t0
    reporter.print_scan_summary(url, 0, 0, len(interesting), len(hits), elapsed)

    if output:
        reporter.save_report({
            "type":           "ssrf_probe",
            "target":         url,
            "parameter":      param,
            "method":         method,
            "json_post":      json_post,
            "total_payloads": len(payloads),
            "ssrf_results":   [r for r in results if "__note__" not in r],
            "oob_hits":       hits,
        }, output)


# ── scan command (full) ───────────────────────────────────────────────────────

@cli.command()
@click.argument("url", required=False)
@click.option("--input",        "-i", "input_file", default=None,                    help="File with URLs (one per line)")
@click.option("--param",        "-p", default=None,                                  help="Parameter for SSRF probe (skipped if omitted)")
@click.option("--method",       "-m", default="GET",
              type=click.Choice(["GET", "POST"], case_sensitive=False))
@click.option("--json-post",          is_flag=True,                                  help="POST as JSON")
@click.option("--max-files",          default=60,    show_default=True,              help="Max JS files to scan")
@click.option("--cloud",        "-c", multiple=True)
@click.option("--listen",             is_flag=True,                                  help="Start local OOB listener")
@click.option("--oob",                default=None,                                  help="External OOB host")
@click.option("--timeout",      "-t", default=10,    show_default=True)
@click.option("--output",       "-o", default=None,                                  help="Save JSON report to file")
@global_options
def scan(url, input_file, param, method, json_post, max_files, cloud, listen, oob, timeout, output,
         proxy, cookie, headers, verbose):
    """Full scan: JS Secret Harvest AND SSRF Probe Chain.

    \b
    Examples:
      python rxhunt.py scan https://example.com
      python rxhunt.py scan https://example.com --param url --listen -o report.json
      python rxhunt.py scan https://example.com --proxy http://127.0.0.1:8080 --verbose
      python rxhunt.py scan --input urls.txt --param redirect -o full_report.json
    """
    urls = _resolve_targets(url, input_file)
    extra_headers = parse_headers(headers)
    asyncio.run(_scan_multi(
        urls, param, method.upper(), json_post, max_files, list(cloud),
        listen, oob, timeout, output, proxy, cookie, extra_headers, verbose,
    ))


async def _scan_multi(urls, param, method, json_post, max_files, clouds,
                      listen, oob, timeout, output, proxy, cookie, extra_headers, verbose):
    for target_url in urls:
        await _scan(target_url, param, method, json_post, max_files, clouds,
                    listen, oob, timeout, output, proxy, cookie, extra_headers, verbose)


async def _scan(url, param, method, json_post, max_files, clouds, listen, oob,
                timeout, output, proxy, cookie, extra_headers, verbose):
    t0 = time.monotonic()

    console.print(f"\n  [bold cyan]Full Scan Target:[/bold cyan] {url}")
    if proxy:
        console.print(f"  [dim]Proxy: {proxy}[/dim]")
    console.print()

    # ── Phase 1: JS Harvest ──────────────────────────────────────────────
    reporter.print_section("1 / 2  JS Secret Harvest")

    harvester = JSHarvester(
        url, timeout=timeout, max_js_files=max_files,
        verbose=verbose, proxy=proxy,
        extra_headers=extra_headers, cookies=cookie,
    )

    with make_progress() as prog:
        t = prog.add_task("Discovering JS files...", total=None)
        js_files = await harvester.discover_js_files()
        prog.update(t, total=1, completed=1, description=f"Discovered {len(js_files)} JS files")

    reporter.print_js_file_list(js_files)

    js_findings = []
    if js_files:
        with make_progress() as prog:
            task = prog.add_task("Scanning JS files...", total=len(js_files))

            def on_js(current, total, js_url):
                prog.update(task, completed=current)

            js_findings = await harvester.run(progress_callback=on_js)

        reporter.print_js_findings(js_findings)
    else:
        console.print("  [dim]No JS files found.[/dim]")

    # ── Phase 2: SSRF Probe ──────────────────────────────────────────────
    ssrf_results = []
    hits = []

    if param:
        reporter.print_section("2 / 2  SSRF Probe Chain")

        oob_listener = None
        if listen:
            oob_listener = OOBListener()
            local_ip = oob_listener.get_local_ip()
            try:
                await oob_listener.start()
                oob = oob or f"{local_ip}:{oob_listener.port}"
                console.print(f"  [green]OOB Listener: {oob}[/green]\n")
            except OSError as e:
                console.print(f"  [yellow]OOB listener failed: {e}[/yellow]")
                oob_listener = None

        ssrf = SSRFProbe(
            target_url=url, parameter=param,
            oob_host=oob, timeout=timeout,
            clouds=clouds if clouds else None,
            json_post=json_post, verbose=verbose,
            proxy=proxy, extra_headers=extra_headers, cookies=cookie,
        )

        payloads = ssrf.build_all_payloads()
        console.print(f"  [dim]Payloads: {len(payloads)}[/dim]\n")

        with make_progress() as prog:
            task = prog.add_task("Running SSRF probes...", total=len(payloads))

            def on_ssrf(current, total, pu):
                prog.update(task, completed=current)

            ssrf_results = await ssrf.run(method=method, progress_callback=on_ssrf)

        reporter.print_ssrf_results(ssrf_results)

        if oob_listener:
            await asyncio.sleep(2)
            hits = oob_listener.get_hits()
            reporter.print_oob_hits(hits)
            await oob_listener.stop()

    else:
        reporter.print_section("2 / 2  SSRF Probe Chain")
        console.print("  [dim]Skipped — use --param to enable SSRF probing.[/dim]")

    interesting = [
        r for r in ssrf_results
        if isinstance(r, dict)
        and r.get("indication") not in ("none", "error", None)
        and "__note__" not in r
    ]

    elapsed = time.monotonic() - t0
    reporter.print_scan_summary(
        url, len(js_files), len(js_findings), len(interesting), len(hits), elapsed
    )

    if output:
        reporter.save_report({
            "type":         "full_scan",
            "target":       url,
            "js_files":     js_files,
            "js_findings":  js_findings,
            "ssrf_results": [r for r in ssrf_results if "__note__" not in r],
            "oob_hits":     hits,
        }, output)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _resolve_targets(url_arg, input_file) -> list:
    """
    Resolve the final list of target URLs from either a CLI argument
    or a --input file. Errors if neither is provided.
    """
    if input_file:
        urls = load_url_list(input_file)
        console.print(f"  [dim]Loaded {len(urls)} targets from {input_file}[/dim]\n")
        return urls
    if url_arg:
        return [validate_url(url_arg)]
    console.print("  [red]Error: provide a URL argument or --input <file>[/red]")
    sys.exit(1)


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
