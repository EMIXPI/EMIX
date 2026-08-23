"""
transports/xhttp.py — XHTTP Transport Adapter (packet-up / stream-up)
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from transports import AbstractTransport, register_transport


class XHTTPTransport(AbstractTransport):
    """ترنسپورت XHTTP (SplitHTTP) — جایگزین مدرن WebSocket با multiplexing بهتر."""

    name = "xhttp"
    label = "XHTTP (Packet-Up)"
    protocol_key = "xhttp-packet-up"
    _mode: str = "packet-up"

    def validate(self, params: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        mode = params.get("mode", self._mode)
        if mode not in ("packet-up", "stream-up"):
            errors.append("mode باید packet-up یا stream-up باشد")
        return errors

    def render(self, params: Dict[str, Any]) -> Dict[str, Any]:
        mode = params.get("mode", self._mode)
        path = params.get("path", f"/xhttp-siz10/{mode}/{{uuid}}")
        return {
            "network": "xhttp",
            "security": "tls",
            "xhttpSettings": {
                "mode": mode,
                "path": path,
                "host": params.get("host", ""),
            },
            "tlsSettings": {
                "serverName": params.get("sni", params.get("host", "")),
                "allowInsecure": params.get("allow_insecure", False),
                "fingerprint": params.get("fingerprint", "chrome"),
                "alpn": [params.get("alpn", "h2")],
            },
        }

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        mode = params.get("mode", self._mode)
        path = params.get("path", f"/xhttp-siz10/{mode}/{uuid}")
        return {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": params.get("fingerprint", "chrome"),
            "alpn": params.get("alpn", "h2"),
        }


class XHTTPStreamUpTransport(XHTTPTransport):
    """نسخه‌ی stream-up (دانلود طولانی)."""

    _mode = "stream-up"
    protocol_key = "xhttp-stream-up"
    label = "XHTTP (Stream-Up)"


class TrojanXHTTPPacketUpTransport(XHTTPTransport):
    """نسخه‌ی Trojan برای XHTTP packet-up."""

    protocol_key = "trojan-xhttp-packet-up"
    label = "Trojan · XHTTP Packet-Up"

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        mode = params.get("mode", "packet-up")
        path = params.get("path", f"/txhttp-siz10/{mode}/{uuid}")
        return {
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": params.get("fingerprint", "chrome"),
            "alpn": params.get("alpn", "h2"),
        }

    def share_link(self, uuid: str, host: str, remark: str = "EMIX",
                   params = None, scheme: str = "trojan") -> str:
        return super().share_link(uuid, host, remark, params, scheme)


class TrojanXHTTPStreamUpTransport(TrojanXHTTPPacketUpTransport):
    protocol_key = "trojan-xhttp-stream-up"
    label = "Trojan · XHTTP Stream-Up"


# ثبت تمام نسخه‌های XHTTP
register_transport(XHTTPTransport())
register_transport(XHTTPStreamUpTransport())
register_transport(TrojanXHTTPPacketUpTransport())
register_transport(TrojanXHTTPStreamUpTransport())