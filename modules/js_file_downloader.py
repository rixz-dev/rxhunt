"""
JS File Downloader
Parses JS content for referenced sensitive file paths, then attempts to
download them from the target origin.

Why this matters in bug bounty:
  - Source maps (.js.map) → original source code, comments, sometimes hardcoded creds
  - Config endpoints (/api/config, /api/settings) → live config data
  - Hardcoded paths to sensitive files (/.env.production, /backup.sql.gz)
  - Webpack chunk manifest → reveals internal route structure
  - Swagger/OpenAPI specs → full API surface exposed
"""

import asyncio
import os
import re
import sys
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urljoin, urlparse

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

try:
    import httpx
except ImportError:
    print("[!] Missing httpx. Run: pip install httpx --break-system-packages")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.patterns import PATTERNS

# ── Patterns that identify referenced files/paths inside JS ──────────────────

# 1. Source map references (goldmine — contains original source)
_PAT_SOURCEMAP = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*([^\s"\']+\.map)',
    re.IGNORECASE,
)

# 2. Sensitive file extensions referenced as strings
_PAT_SENSITIVE_EXT = re.compile(
    r'["\'`]([^"\'`\s]{1,200}'
    r'\.(?:env|json|xml|yml|yaml|conf|config|ini|sql|sql\.gz|bak|backup|old|dump|db|sqlite|pem|key|crt|pfx|p12)'
    r')["\'\`]',
    re.IGNORECASE,
)

# 3. Config/settings API endpoints referenced in fetch/axios/XHR calls
_PAT_CONFIG_ENDPOINT = re.compile(
    r'(?:fetch|axios\.(?:get|post)|XMLHttpRequest|\.open)\s*\(\s*["\'`]'
    r'(/[^"\'`\s]{0,100}(?:config|settings|env|secret|admin|swagger|openapi|api-docs|manifest)[^"\'`\s]{0,80})'
    r'["\'`]',
    re.IGNORECASE,
)

# 4. Well-known sensitive web paths hardcoded in JS
_PAT_KNOWN_PATHS = re.compile(
    r'["\'`]('
    r'/?\.git/(?:config|HEAD|COMMIT_EDITMSG)|'
    r'/?\.env(?:\.\w+)?|'
    r'/?wp-config\.php|'
    r'/?web\.config|'
    r'/?appsettings(?:\.\w+)?\.json|'
    r'/?(?:phpinfo|info)\.php|'
    r'/?(?:swagger|openapi|api-docs?)(?:\.json|\.yaml|\.yml)?|'
    r'/?(?:backup|dump|db)(?:\.\w+)+|'
    r'/?package\.json|'
    r'/?composer\.json|'
    r'/?Gemfile\.lock|'
    r'/?requirements\.txt|'
    r'/?\.DS_Store'
    r')["\'`]',
    re.IGNORECASE,
)

# 5. Webpack chunk manifest (/_next/static, /static/js chunk references)
_PAT_WEBPACK_CHUNKS = re.compile(
    r'["\'`](/(?:_next/static|static/js|assets/js|dist)/[^"\'`\s]+\.js(?:\?[^"\'`\s]*)?)["\'\`]'
)

FETCH_CONCURRENCY = 8

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
}


def extract_referenced_paths(js_content: str, js_url: str) -> List[Dict[str, str]]:
    """
    Parse a single JS file's content and extract all referenced file paths.
    Returns list of {path, type, source_js} dicts.
    """
    refs: List[Dict[str, str]] = []
    seen_paths: set = set()

    def _add(path: str, ref_type: str) -> None:
        path = path.strip()
        if not path or path in seen_paths:
            return
        # Skip obvious non-paths
        if len(path) < 2 or len(path) > 250:
            return
        if any(skip in path for skip in ("${", "#{", "<%", "{{")):
            return  # template literals / interpolations → not real paths
        seen_paths.add(path)
        refs.append({"path": path, "type": ref_type, "source_js": js_url})

    for m in _PAT_SOURCEMAP.finditer(js_content):
        _add(m.group(1), "source_map")

    for m in _PAT_SENSITIVE_EXT.finditer(js_content):
        _add(m.group(1), "sensitive_file_ref")

    for m in _PAT_CONFIG_ENDPOINT.finditer(js_content):
        _add(m.group(1), "config_endpoint")

    for m in _PAT_KNOWN_PATHS.finditer(js_content):
        _add(m.group(1), "known_sensitive_path")

    for m in _PAT_WEBPACK_CHUNKS.finditer(js_content):
        _add(m.group(1), "webpack_chunk")

    return refs


def resolve_url(base_url: str, path: str) -> Optional[str]:
    """
    Resolve a discovered path against the target base URL.
    Handles: absolute paths (/foo), relative paths (./foo), full URLs.
    """
    if not path:
        return None

    # Already a full URL
    if path.startswith(("http://", "https://")):
        return path

    # Source map relative to the JS file location
    if not path.startswith("/"):
        return urljoin(base_url, path)

    # Absolute path → apply to target origin
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return origin + path


def _scan_content_for_secrets(content: str, source_url: str) -> List[Dict[str, Any]]:
    """Run pattern matching on downloaded file content. Reuses PATTERNS from config."""
    findings = []
    seen: set = set()
    for name, (pattern, severity, description) in PATTERNS.items():
        for match in pattern.finditer(content):
            value = match.group(0)
            key = (name, value[:60])
            if key in seen:
                continue
            seen.add(key)
            start = max(0, match.start() - 60)
            end = min(len(content), match.end() + 60)
            findings.append({
                "type": name,
                "description": description,
                "value": value[:200],
                "severity": severity,
                "source": source_url,
                "context": content[start:end].replace("\n", " ").strip()[:350],
                "detection": "pattern",
            })
    return findings


class JSFileDownloader:
    def __init__(
        self,
        target_url: str,
        timeout: int = 12,
        output_dir: Optional[str] = None,
        verbose: bool = False,
        proxy: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        scan_downloaded: bool = True,
    ):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.output_dir = output_dir
        self.verbose = verbose
        self.scan_downloaded = scan_downloaded

        merged_headers = {**HEADERS, **(extra_headers or {})}
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

        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)

    def _output_path(self, url: str) -> str:
        """Generate a safe local filename from a URL."""
        parsed = urlparse(url)
        name = parsed.path.replace("/", "_").lstrip("_") or "index"
        if parsed.query:
            # Truncate long query strings
            name += "_" + parsed.query[:40].replace("=", "-").replace("&", "_")
        # Sanitize
        name = re.sub(r'[^\w.\-]', '_', name)
        return os.path.join(self.output_dir, name[:120])

    def parse_all_refs(
        self, js_contents: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """
        Given list of {url, content} dicts (from harvester), extract all
        referenced paths and resolve them to full URLs.

        Returns deduplicated list of {resolved_url, path, type, source_js}.
        """
        all_refs: List[Dict[str, str]] = []
        seen_resolved: set = set()

        for item in js_contents:
            js_url = item["url"]
            content = item["content"]
            refs = extract_referenced_paths(content, js_url)
            for ref in refs:
                resolved = resolve_url(js_url, ref["path"])
                if not resolved or resolved in seen_resolved:
                    continue
                seen_resolved.add(resolved)
                all_refs.append({**ref, "resolved_url": resolved})

        if self.verbose:
            print(f"[verbose] downloader: {len(all_refs)} unique paths extracted")

        return all_refs

    async def _try_download(
        self, client: httpx.AsyncClient, ref: Dict[str, str]
    ) -> Dict[str, Any]:
        """Attempt to fetch one referenced URL. Returns result dict."""
        url = ref["resolved_url"]
        result: Dict[str, Any] = {
            "url": url,
            "path": ref["path"],
            "type": ref["type"],
            "source_js": ref["source_js"],
            "status": None,
            "size": 0,
            "saved_to": None,
            "content_preview": "",
            "secrets_found": [],
            "downloaded": False,
        }
        try:
            resp = await client.get(url)
            result["status"] = resp.status_code

            if resp.status_code == 200 and len(resp.content) > 0:
                result["downloaded"] = True
                result["size"] = len(resp.content)
                result["content_preview"] = resp.text[:500]

                # Save to disk if output_dir configured
                if self.output_dir:
                    local_path = self._output_path(url)
                    with open(local_path, "wb") as f:
                        f.write(resp.content)
                    result["saved_to"] = local_path

                # Run secret scan on downloaded content
                if self.scan_downloaded:
                    result["secrets_found"] = _scan_content_for_secrets(resp.text, url)

            elif self.verbose:
                print(f"[verbose] download: HTTP {resp.status_code} → {url}")

        except httpx.TimeoutException:
            result["status"] = "timeout"
            if self.verbose:
                print(f"[verbose] download: timeout → {url}")
        except httpx.RequestError as e:
            result["status"] = "error"
            if self.verbose:
                print(f"[verbose] download: request error → {url} ({e})")

        return result

    async def run(
        self,
        js_contents: List[Dict[str, str]],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> Dict[str, Any]:
        """
        Full download run.

        Args:
            js_contents: list of {url: str, content: str} from JSHarvester
            progress_callback: (current, total, url) -> None

        Returns:
            {
                "refs_found": int,
                "downloaded": list of successful result dicts,
                "failed": list of failed result dicts,
                "secrets_in_downloads": list of all secret findings,
            }
        """
        refs = self.parse_all_refs(js_contents)
        total = len(refs)
        completed = 0
        sem = asyncio.Semaphore(FETCH_CONCURRENCY)

        async def guarded_download(client, ref):
            nonlocal completed
            async with sem:
                result = await self._try_download(client, ref)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, ref["resolved_url"])
                return result

        async with httpx.AsyncClient(**self._client_opts) as client:
            tasks = [guarded_download(client, ref) for ref in refs]
            all_results = await asyncio.gather(*tasks)

        downloaded = [r for r in all_results if r["downloaded"]]
        failed = [r for r in all_results if not r["downloaded"]]
        secrets: List[Dict[str, Any]] = []
        for r in downloaded:
            secrets.extend(r.get("secrets_found", []))

        return {
            "refs_found": total,
            "downloaded": downloaded,
            "failed": failed,
            "secrets_in_downloads": secrets,
        }
