"""
transports/hysteria2.py — Hysteria2 Transport (sing-box)
════════════════════════════════════════════════════════════
پیاده‌سازی placeholder برای Hysteria2. این پروتکل بر پایه QUIC است و
نیاز به هسته‌ی sing-box دارد. کانفیگ مناسب برای sing-box تولید می‌کند.

در صورت عدم وجود sing-box در سرور، این ترنسپورت صرفاً لینک و کانفیگ
کلاینت را تولید می‌کند و inbound واقعی ایجاد نمی‌شود.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from transports import (
    AbstractTransport,
    register_transport,
    generate_password,
)


class Hysteria2Transport(AbstractTransport):
    """ترنسپورت Hysteria2 — پروتکل پرسرعت QUIC برای عبور از DPI.

    Hysteria2 از QUIC استفاده می‌کند و نسبت به TCP-based پروتکل‌ها
    در شبکه‌های پرتاخیر عملکرد بهتری دارد. همچنین با obfuscation
    داخلی، تشخیص آن توسط DPI سخت‌تر است.
    """

    name = "hysteria2"
    label = "Hysteria2 (QUIC)"
    protocol_key = "hysteria2"

    def validate(self, params: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        password = params.get("password", "")
        if not password or len(password) < 8:
            errors.append("password باید حداقل ۸ کاراکتر باشد")
        # obfs password هم باید تنظیم شود
        obfs = params.get("obfs_password", "")
        if obfs and len(obfs) < 8:
            errors.append("obfs_password باید حداقل ۸ کاراکتر باشد")
        return errors

    def render(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """کانفیگ sing-box برای Hysteria2 inbound."""
        password = params.get("password") or generate_password()
        obfs_password = params.get("obfs_password") or password

        return {
            "_engine": "sing-box",
            "_type": "hysteria2",
            "type": "hysteria2",
            "tag": params.get("tag", "hy2-in"),
            "listen": params.get("listen", "::"),
            "listen_port": params.get("port", 443),
            "up_mbps": params.get("up_mbps", 100),
            "down_mbps": params.get("down_mbps", 200),
            "users": [
                {
                    "name": params.get("uuid", ""),
                    "password": password,
                }
            ],
            "tls": {
                "enabled": True,
                "server_name": params.get("server_name") or params.get("sni", ""),
                "alpn": ["h3"],
                "certificate_path": params.get("cert_path", "/etc/ssl/cert.pem"),
                "key_path": params.get("key_path", "/etc/ssl/key.pem"),
            },
            "obfs": {
                "type": "salamander",
                "salamander": {
                    "password": obfs_password,
                },
            },
            "masquerade": params.get("masquerade", "https://www.bing.com/"),
            "ignore_client_bandwidth": params.get("ignore_bandwidth", False),
        }

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        """پارامترهای لینک hysteria2:// برای کلاینت."""
        password = params.get("password", "")
        sni = params.get("server_name") or params.get("sni", host)
        obfs_password = params.get("obfs_password", password)
        port = params.get("port", 443)

        result = {
            "sni": sni,
            "insecure": "0",
            "alpn": "h3",
            "obfs": "salamander",
            "obfs-password": obfs_password,
        }
        return result

    def share_link(
        self,
        uuid: str,
        host: str,
        remark: str = "EMIX",
        params: Dict[str, Any] | None = None,
        scheme: str = "hysteria2",
    ) -> str:
        """لینک hysteria2:// یا hy2://"""
        if params is None:
            params = {}
        password = params.get("password", "")
        sni = params.get("server_name") or params.get("sni", host)
        port = params.get("port", 443)
        obfs_pw = params.get("obfs_password", password)

        # فرمت: hysteria2://password@host:port?sni=...&insecure=1
        link = f"hysteria2://{quote(password)}@{host}:{port}?"
        link += f"sni={quote(sni)}&alpn=h3"
        # پل EMIX با گواهی self-signed سرو می‌کند؛ پیش‌فرض insecure=1 است.
        link += f"&insecure={params.get('insecure', '1')}"
        obfs_pw = params.get("obfs_password")
        if obfs_pw:
            link += f"&obfs=salamander&obfs-password={quote(obfs_pw)}"
        link += f"#{quote(remark)}"
        return link


register_transport(Hysteria2Transport())