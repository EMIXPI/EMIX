"""
transports/reality.py — REALITY + XTLS Vision Transport
════════════════════════════════════════════════════════════
پیاده‌سازی کامل ترنسپورت REALITY با XTLS Vision برای دور زدن DPI.

ویژگی‌ها:
  - streamSettings.security = "reality"
  - flow = "xtls-rprx-vision"
  - قابلیت تنظیم serverName از لیست SNI
  - تولید خودکار privateKey با x25519
  - پشتیبانی از shortIds
  - fingerprint قابل تنظیم
  - تولید inbound و outbound کامل
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from transports import (
    AbstractTransport,
    register_transport,
    generate_x25519_keypair,
    generate_short_id,
    get_random_sni,
)


class RealityTransport(AbstractTransport):
    """ترنسپورت REALITY — امن‌ترین روش دور زدن DPI با XTLS Vision.

    REALITY ترافیک VLESS را شبیه TLS عادی به یک سایت معتبر (serverName) می‌کند.
    برخلاف TLS معمولی، نیازی به گواهی SSL ندارد و از کلید عمومی دامنه‌ی مقصد
    برای handshake استفاده می‌کند.
    """

    name = "reality"
    label = "REALITY + Vision"
    protocol_key = "vless-reality"

    def validate(self, params: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        sni = params.get("server_name") or params.get("sni", "")
        if sni and (not sni or "." not in sni):
            errors.append("serverName باید یک دامنه‌ی معتبر باشد (مثلاً digikala.com)")
        fingerprint = params.get("fingerprint", "chrome")
        valid_fps = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
        if fingerprint not in valid_fps:
            errors.append(f"fingerprint نامعتبر. مقادیر مجاز: {', '.join(valid_fps)}")
        return errors

    def render(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """streamSettings کامل برای REALITY inbound/outbound."""
        sni = params.get("server_name") or params.get("sni") or get_random_sni()
        private_key = params.get("private_key") or generate_x25519_keypair()[0]
        short_ids = params.get("short_ids") or [generate_short_id(8)]
        if isinstance(short_ids, str):
            short_ids = [short_ids]
        fingerprint = params.get("fingerprint", "chrome")
        server_port = params.get("server_port", 443)  # پورت مقصد برای فریب
        dest = params.get("dest") or f"{sni}:{server_port}"

        reality_settings: Dict[str, Any] = {
            "serverName": sni,
            "privateKey": private_key,
            "shortIds": short_ids,
            "fingerprint": fingerprint,
            "show": False,
            "spiderX": params.get("spider_x", "/"),
        }

        # serverNames اختیاری برای فریب بهتر
        if params.get("server_names"):
            reality_settings["serverNames"] = params["server_names"]

        # publicKey می‌تواند به‌جای privateKey استفاده شود (برای کلاینت)
        if params.get("public_key"):
            reality_settings["publicKey"] = params["public_key"]

        result: Dict[str, Any] = {
            "network": params.get("network", "tcp"),
            "security": "reality",
            "realitySettings": reality_settings,
        }

        # flow فقط برای inbound
        if params.get("include_flow", True):
            result["flow"] = "xtls-rprx-vision"

        # TCP settings
        if params.get("tfo", True):
            result["tcpSettings"] = {
                "header": {"type": params.get("tcp_header", "none")}
            }
            result["sockopt"] = {
                "tfo": True,
                "tcpFastOpen": True,
            }

        return result

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        """پارامترهای لینک vless:// برای کلاینت.

        نکته: در کلاینت، security=reality و flow=xtls-rprx-vision باید
        در خروجی لحاظ شود. همچنین pbk (publicKey) و sid (shortId) ضروری هستند.
        """
        sni = params.get("server_name") or params.get("sni", "")
        fingerprint = params.get("fingerprint", "chrome")
        public_key = params.get("public_key", "")
        short_id = ""
        if params.get("short_ids"):
            sids = params["short_ids"]
            short_id = sids[0] if isinstance(sids, list) else sids

        result = {
            "encryption": "none",
            "security": "reality",
            "flow": "xtls-rprx-vision",
            "type": params.get("type", "tcp"),
            "sni": sni,
            "fp": fingerprint,
            "alpn": params.get("alpn", "h2,http/1.1"),
        }

        if public_key:
            result["pbk"] = public_key
        if short_id:
            result["sid"] = short_id
        if params.get("spider_x"):
            result["spx"] = params["spider_x"]

        return result

    def render_outbound(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """streamSettings برای outbound (کلاینت Xray)."""
        sni = params.get("server_name") or params.get("sni") or get_random_sni()
        return {
            "network": "tcp",
            "security": "reality",
            "flow": "xtls-rprx-vision",
            "realitySettings": {
                "serverName": sni,
                "fingerprint": params.get("fingerprint", "chrome"),
                "publicKey": params.get("public_key", ""),
                "shortId": (params.get("short_ids") or [""])[0] if isinstance(params.get("short_ids"), list) else params.get("short_ids", ""),
                "spiderX": params.get("spider_x", "/"),
            },
            "tcpSettings": {"header": {"type": "none"}},
            "sockopt": {"tfo": True},
        }


# ثبت ترنسپورت REALITY
register_transport(RealityTransport())

# نسخه‌ی REALITY + gRPC
class RealityGrpcTransport(RealityTransport):
    """REALITY روی gRPC (برای دور زدن DPI با پروتکل gRPC)."""

    name = "grpc"
    label = "REALITY + gRPC"
    protocol_key = "vless-reality-grpc"

    def render(self, params: Dict[str, Any]) -> Dict[str, Any]:
        base = super().render(params)
        base["network"] = "grpc"
        service_name = params.get("service_name", "GunService")
        base["grpcSettings"] = {
            "serviceName": service_name,
            "multiMode": params.get("multi_mode", False),
        }
        return base

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        base = super().share_params(uuid, host, params)
        base["type"] = "grpc"
        base["serviceName"] = params.get("service_name", "GunService")
        if params.get("multi_mode"):
            base["mode"] = "multi"
        return base


register_transport(RealityGrpcTransport())