"""
transports/grpc.py — gRPC Transport Adapter
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from transports import AbstractTransport, register_transport


class GrpcTransport(AbstractTransport):
    """ترنسپورت gRPC + TLS — برای شرایطی که WebSocket بسته شده."""

    name = "grpc"
    label = "gRPC"
    protocol_key = "vless-grpc"

    def validate(self, params: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        service = params.get("service_name", "")
        if not service or not service.strip():
            errors.append("serviceName نمی‌تواند خالی باشد")
        return errors

    def render(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "network": "grpc",
            "security": "tls",
            "grpcSettings": {
                "serviceName": params.get("service_name", "GunService"),
                "multiMode": params.get("multi_mode", False),
            },
            "tlsSettings": {
                "serverName": params.get("sni", params.get("host", "")),
                "allowInsecure": params.get("allow_insecure", False),
                "fingerprint": params.get("fingerprint", "chrome"),
                "alpn": [params.get("alpn", "h2")],
            },
        }

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        return {
            "encryption": "none",
            "security": "tls",
            "type": "grpc",
            "serviceName": params.get("service_name", "GunService"),
            "host": host,
            "sni": host,
            "fp": params.get("fingerprint", "chrome"),
            "alpn": params.get("alpn", "h2"),
            "mode": "multi" if params.get("multi_mode") else "gun",
        }


@register_transport
class TrojanGrpcTransport(GrpcTransport):
    """نسخه‌ی Trojan از gRPC."""

    label = "Trojan · gRPC"
    protocol_key = "trojan-grpc"

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        base = super().share_params(uuid, host, params)
        base.pop("encryption", None)
        return base

    def share_link(self, uuid: str, host: str, remark: str = "EMIX",
                   params: Dict[str, Any] | None = None, scheme: str = "trojan") -> str:
        return super().share_link(uuid, host, remark, params, scheme)


register_transport(GrpcTransport())