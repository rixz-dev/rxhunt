"""
OOB (Out-of-Band) Listener
Lightweight asyncio TCP/HTTP server that catches incoming callbacks
from SSRF probes. Self-hosted Burp Collaborator alternative.
"""

import asyncio
import socket
import time
from datetime import datetime
from typing import List, Dict, Any, Optional


class OOBListener:
    def __init__(self, host: str = "0.0.0.0", port: int = 8765):
        self.host = host
        self.port = port
        self.hits: List[Dict[str, Any]] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._started = False

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        addr = writer.get_extra_info("peername") or ("unknown", 0)
        recv_time = datetime.now().isoformat()

        try:
            # Read up to 8KB of data
            raw = await asyncio.wait_for(reader.read(8192), timeout=5.0)
            decoded = raw.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            decoded = "(read timeout)"
        except Exception as e:
            decoded = f"(read error: {e})"

        # Parse HTTP method + path if it looks like HTTP
        method = path = ""
        lines = decoded.split("\r\n")
        if lines and " " in lines[0]:
            parts = lines[0].split(" ")
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else ""

        hit = {
            "id": len(self.hits) + 1,
            "timestamp": recv_time,
            "remote_ip": addr[0],
            "remote_port": addr[1],
            "method": method,
            "path": path,
            "raw_preview": decoded[:500],
            "size": len(raw) if isinstance(raw, bytes) else 0,
        }
        self.hits.append(hit)

        # Respond with HTTP 200 so the target server gets a valid response
        http_resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 7\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"rxhunt\r\n"
        )
        try:
            writer.write(http_resp)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        """Start the OOB listener server."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
        )
        self._started = True

    async def stop(self) -> None:
        """Stop the listener."""
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=3.0)
            except asyncio.TimeoutError:
                pass
        self._started = False

    def get_hits(self) -> List[Dict[str, Any]]:
        return list(self.hits)

    def has_hits(self) -> bool:
        return len(self.hits) > 0

    def get_local_ip(self) -> str:
        """Get local LAN IP for use as OOB host."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @property
    def listen_address(self) -> str:
        return f"{self.get_local_ip()}:{self.port}"

    def is_running(self) -> bool:
        return self._started and self._server is not None
