"""
transports/websocket.py — WebSocket Transport Adapter
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from transports import AbstractTransport, register_transport


class WebSocketTransport(AbstractTransport):
    """ترنسپورت WebSocket + TLS (پروتکل موجود و پرکاربرد)."""

    name = "ws"
    label = "WebSocket (WS)"
    protocol_key = "vless-ws"

    def validate(self, params: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        path = params.get("path", "")
        if not path or not path.startswith("/"):
            errors.append("path باید با / شروع شود")
        return errors

    def render(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": params.get("path", "/ws"),
                "headers": params.get("headers", {}),
            },
            "tlsSettings": {
                "serverName": params.get("sni", params.get("host", "")),
                "allowInsecure": params.get("allow_insecure", False),
                "fingerprint": params.get("fingerprint", "chrome"),
                "alpn": [params.get("alpn", "h2")],
            },
        }

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        path = params.get("path", f"/ws/{uuid}")
        return {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": params.get("fingerprint", "chrome"),
            "alpn": params.get("alpn", "h2"),
        }


@register_transport
class TrojanWebSocketTransport(WebSocketTransport):
    """نسخه‌ی Trojan ترنسپورت WebSocket."""

    name = "ws"
    label = "Trojan · WebSocket"
    protocol_key = "trojan-ws"

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        path = params.get("path", "/trojan-ws")
        return {
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": params.get("fingerprint", "chrome"),
            "alpn": params.get("alpn", "h2"),
        }

    def share_link(self, uuid: str, host: str, remark: str = "EMIX",
                   params: Dict[str, Any] | None = None, scheme: str = "trojan") -> str:
        return super().share_link(uuid, host, remark, params, scheme)


# ثبت نسخه‌ی اصلی VLESS WS
register_transport(WebSocketTransport())