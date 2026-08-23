"""
transports/tuic.py — TUIC Transport (placeholder)
═════════════════════════════════════════════════════
TUIC یک پروتکل پراکسی بر پایه QUIC است که توسط sing-box پشتیبانی می‌شود.
در این نسخه صرفاً ساختار کانفیگ کلاینت و سرور آماده شده است.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from transports import (
    AbstractTransport,
    register_transport,
    generate_password,
)


class TUICTransport(AbstractTransport):
    """ترنسپورت TUIC — پروتکل سبک QUIC با multiplexing بالا."""

    name = "tuic"
    label = "TUIC v5 (QUIC)"
    protocol_key = "tuic"

    def validate(self, params: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        password = params.get("password", "")
        if not password or len(password) < 8:
            errors.append("password باید حداقل ۸ کاراکتر باشد")
        return errors

    def render(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """کانفیگ sing-box برای TUIC inbound."""
        password = params.get("password") or generate_password()
        uuid = params.get("uuid", "")

        return {
            "_engine": "sing-box",
            "_type": "tuic",
            "type": "tuic",
            "tag": params.get("tag", "tuic-in"),
            "listen": params.get("listen", "::"),
            "listen_port": params.get("port", 443),
            "users": [
                {
                    "name": uuid,
                    "uuid": uuid,
                    "password": password,
                }
            ],
            "congestion_control": params.get("congestion", "bbr"),
            "tls": {
                "enabled": True,
                "server_name": params.get("server_name") or params.get("sni", ""),
                "alpn": ["h3"],
                "certificate_path": params.get("cert_path", "/etc/ssl/cert.pem"),
                "key_path": params.get("key_path", "/etc/ssl/key.pem"),
            },
        }

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        password = params.get("password", "")
        sni = params.get("server_name") or params.get("sni", host)
        return {
            "sni": sni,
            "alpn": "h3",
            "congestion_control": params.get("congestion", "bbr"),
        }

    def share_link(
        self,
        uuid: str,
        host: str,
        remark: str = "EMIX",
        params: Dict[str, Any] | None = None,
        scheme: str = "tuic",
    ) -> str:
        if params is None:
            params = {}
        password = params.get("password", "")
        sni = params.get("server_name") or params.get("sni", host)
        port = params.get("port", 443)
        congestion = params.get("congestion", "bbr")

        link = f"tuic://{quote(uuid)}:{quote(password)}@{host}:{port}?"
        link += f"sni={quote(sni)}&alpn=h3&congestion_control={congestion}"
        # پل EMIX با گواهی self-signed سرو می‌کند؛ کلاینت‌ها allow_insecure=1 لازم دارند
        insecure = str(params.get("insecure", "1"))
        link += f"&udp_relay_mode=native&allow_insecure={insecure}"
        link += f"#{quote(remark)}"
        return link


register_transport(TUICTransport())