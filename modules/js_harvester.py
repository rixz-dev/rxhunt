"""
JS Secret Harvester
Crawls JS files from a target, extracts secrets via regex + entropy analysis.

Fixes applied vs v1.0.0:
  - Single AsyncClient reused across all fetch_js calls (no TCP handshake per file)
  - Concurrent JS fetching via asyncio.gather + Semaphore(10)
  - Silent exception swallowed in discover_js_files → now logs if verbose=True
  - SSL InsecureRequestWarning suppressed via urllib3
  - proxy / extra_headers / cookies wired through client options
"""

import asyncio
import math
import re
import sys
import os
import warnings

# Suppress SSL warnings from verify=False — we know, it's intentional for recon
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.patterns import PATTERNS

try:
    import httpx
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing deps. Run: pip install httpx beautifulsoup4 --break-system-packages")
    sys.exit(1)

from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional, Callable

# Concurrent JS file fetch limit — high enough to be fast, low enough not to trip WAFs
FETCH_CONCURRENCY = 10

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

COMMON_JS_PATHS = [
    "/static/js/main.js",
    "/assets/js/app.js",
    "/js/app.js",
    "/bundle.js",
    "/app.js",
    "/main.js",
    "/dist/bundle.js",
    "/dist/app.js",
    "/_next/static/chunks/main.js",
    "/webpack/main.js",
]


def calculate_entropy(data: str) -> float:
    """Shannon entropy of a string."""
    if not data or len(data) < 2:
        return 0.0
    freq: Dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def find_high_entropy_strings(
    content: str,
    min_length: int = 20,
    max_length: int = 80,
    threshold: float = 4.5,
) -> List[Dict[str, Any]]:
    """Find strings with high Shannon entropy — likely secrets."""
    results = []
    pattern = re.compile(r'["\']([ A-Za-z0-9+/=_\-\.]{%d,%d})["\']' % (min_length, max_length))
    seen: set = set()
    for match in pattern.finditer(content):
        s = match.group(1)
        if s in seen:
            continue
        seen.add(s)
        entropy = calculate_entropy(s)
        if entropy >= threshold:
            results.append({
                "value": s,
                "entropy": round(entropy, 3),
                "position": match.start(),
            })
    return results


class JSHarvester:
    def __init__(
        self,
        target_url: str,
        timeout: int = 12,
        max_js_files: int = 60,
        include_entropy: bool = True,
        verbose: bool = False,
        proxy: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.max_js_files = max_js_files
        self.include_entropy = include_entropy
        self.verbose = verbose
        self.js_files_found: List[str] = []
        self.findings: List[Dict[str, Any]] = []

        # Build merged headers (HEADERS base + any user-supplied extras)
        merged_headers = {**HEADERS, **(extra_headers or {})}

        # Parse cookie string "name=value; name2=value2" → dict
        cookie_dict: Dict[str, str] = {}
        if cookies:
            for part in cookies.split(";"):
                k, _, v = part.strip().partition("=")
                if k:
                    cookie_dict[k.strip()] = v.strip()

        self._client_opts: Dict[str, Any] = {
            "timeout": self.timeout,
            "follow_redirects": True,
            "verify": False,
            "headers": merged_headers,
        }
        if proxy:
            self._client_opts["proxy"] = proxy
        if cookie_dict:
            self._client_opts["cookies"] = cookie_dict

    def _make_client(self) -> httpx.AsyncClient:
        """Create a single reusable AsyncClient. Call once per run()."""
        return httpx.AsyncClient(**self._client_opts)
            
    @property
    def client_opts(self) -> dict:
    """Public read-only access to HTTP client options."""
    return self._client_opts.copy()

    async def discover_js_files(self) -> List[str]:
        """Discover JS file URLs from the target page."""
        js_urls: set = set()
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            async with self._make_client() as client:
                resp = await client.get(self.target_url)
                if resp.status_code != 200:
                    if self.verbose:
                        print(f"[verbose] discover_js_files: HTTP {resp.status_code} for {self.target_url}")
                    return []

                soup = BeautifulSoup(resp.text, "html.parser")

                # <script src="...">
                for tag in soup.find_all("script", src=True):
                    src = tag["src"]
                    if not src or src.startswith("data:"):
                        continue
                    full = urljoin(base, src) if not src.startswith("http") else src
                    if ".js" in full:
                        js_urls.add(full)

                # Common well-known paths
                for path in COMMON_JS_PATHS:
                    js_urls.add(base + path)

                # Inline scripts — webpack chunk references
                inline_pattern = re.compile(r'["\']([ ^"\']+\.js(?:\?[^"\']*)?)["\']')
                for tag in soup.find_all("script"):
                    if not tag.get("src") and tag.string:
                        for m in inline_pattern.finditer(tag.string):
                            candidate = m.group(1)
                            if candidate.startswith("/") or candidate.startswith("http"):
                                full = urljoin(base, candidate) if not candidate.startswith("http") else candidate
                                js_urls.add(full)

        except httpx.TimeoutException as e:
            if self.verbose:
                print(f"[verbose] discover_js_files: timeout — {e}")
        except httpx.RequestError as e:
            if self.verbose:
                print(f"[verbose] discover_js_files: request error — {e}")
        except Exception as e:
            # FIX: was silent `pass` — at least log in verbose mode
            if self.verbose:
                print(f"[verbose] discover_js_files: unexpected error — {type(e).__name__}: {e}")

        self.js_files_found = list(js_urls)[: self.max_js_files]
        return self.js_files_found

    async def fetch_js(self, client: httpx.AsyncClient, url: str) -> Optional[str]:
        """Fetch a single JS file. Reuses provided client — no new TCP handshake."""
        try:
            resp = await client.get(url)
            if resp.status_code == 200 and len(resp.text) > 10:
                return resp.text
            if self.verbose and resp.status_code != 200:
                print(f"[verbose] fetch_js: HTTP {resp.status_code} → {url}")
        except httpx.TimeoutException:
            if self.verbose:
                print(f"[verbose] fetch_js: timeout → {url}")
        except httpx.RequestError as e:
            if self.verbose:
                print(f"[verbose] fetch_js: request error → {url} ({e})")
        except Exception as e:
            if self.verbose:
                print(f"[verbose] fetch_js: error → {url} ({type(e).__name__}: {e})")
        return None

    def extract_secrets(self, content: str, source_url: str) -> List[Dict[str, Any]]:
        """Run all patterns + entropy analysis against JS content."""
        findings = []
        seen_values: set = set()

        # ── Pattern-based ────────────────────────────────────────────────
        for name, (pattern, severity, description) in PATTERNS.items():
            for match in pattern.finditer(content):
                value = match.group(0)
                dedup_key = (name, value[:60])
                if dedup_key in seen_values:
                    continue
                seen_values.add(dedup_key)

                # Context window (±60 chars)
                start = max(0, match.start() - 60)
                end = min(len(content), match.end() + 60)
                context = content[start:end].replace("\n", " ").strip()

                findings.append({
                    "type": name,
                    "description": description,
                    "value": value[:200],
                    "severity": severity,
                    "source": source_url,
                    "context": context[:350],
                    "detection": "pattern",
                })

        # ── Entropy-based ────────────────────────────────────────────────
        if self.include_entropy:
            high_entropy = find_high_entropy_strings(content)
            for item in high_entropy:
                s = item["value"]
                already_caught = any(s in f["value"] for f in findings)
                if already_caught:
                    continue
                dedup_key = ("entropy", s[:60])
                if dedup_key in seen_values:
                    continue
                seen_values.add(dedup_key)

                findings.append({
                    "type": "high_entropy_string",
                    "description": f"High-entropy string (e={item['entropy']})",
                    "value": s,
                    "severity": "LOW",
                    "source": source_url,
                    "context": f"Entropy: {item['entropy']} — possibly a token or key",
                    "detection": "entropy",
                })

        return findings

    async def run(
        self,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Full harvest run.
        - Single AsyncClient shared across all JS fetches (no per-file TCP overhead)
        - Concurrent fetches via asyncio.gather + Semaphore(FETCH_CONCURRENCY)
        """
        if not self.js_files_found:
            await self.discover_js_files()

        total = len(self.js_files_found)
        all_findings: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(FETCH_CONCURRENCY)
        completed = 0

        async def fetch_and_scan(client: httpx.AsyncClient, js_url: str) -> List[Dict[str, Any]]:
            nonlocal completed
            async with sem:
                content = await self.fetch_js(client, js_url)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, js_url)
                if content:
                    return self.extract_secrets(content, js_url)
                return []

        # FIX: Single client reused by all concurrent tasks
        async with self._make_client() as client:
            tasks = [fetch_and_scan(client, url) for url in self.js_files_found]
            results = await asyncio.gather(*tasks)

        for batch in results:
            all_findings.extend(batch)

        # Global deduplication by (type, value[:50])
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for f in all_findings:
            key = (f["type"], f["value"][:50])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        self.findings = unique
        return unique
