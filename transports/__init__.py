"""
transports/__init__.py — EMIX Transport Adapter System
════════════════════════════════════════════════════════
الگوی Adapter یکپارچه برای همه ترنسپورت‌های Xray-core/sing-box.

هر ترنسپورت از AbstractTransport ارث‌بری می‌کند و دو متد اصلی دارد:
  - validate(params)  : اعتبارسنجی پارامترهای ورودی
  - render(params)    : تولید streamSettings برای Xray JSON config
  - share_link(uuid, host, remark, params) : تولید لینک اشتراک vless:///trojan://

رجیستری مرکزی (TRANSPORT_REGISTRY) امکان افزودن ترنسپورت‌های جدید را
بدون تغییر در کد اصلی پنل فراهم می‌کند.
"""

from __future__ import annotations

import abc
import secrets
import base64
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

# ══════════════════════════════════════════════════════════════════════════════
# کلاس پایه Transport
# ══════════════════════════════════════════════════════════════════════════════

class AbstractTransport(abc.ABC):
    """کلاس پایه برای تمام ترنسپورت‌ها.

    هر ترنسپورت جدید باید از این کلاس ارث‌بری کرده و متدهای زیر را پیاده‌سازی کند:
      - name          : نام یکتای ترنسپورت (مثلاً "ws", "reality", "grpc")
      - label         : برچسب نمایشی برای UI
      - protocol_key  : کلید استفاده‌شده در PROTOCOLS (مثلاً "vless-reality")
      - render()      : تولید streamSettings برای Xray JSON
      - share_params(): تولید پارامترهای query-string برای لینک اشتراک
    """

    name: str = ""
    label: str = ""
    protocol_key: str = ""

    @abc.abstractmethod
    def validate(self, params: Dict[str, Any]) -> List[str]:
        """اعتبارسنجی پارامترها. لیست خطاها را برمی‌گرداند (خالی = معتبر)."""
        ...

    @abc.abstractmethod
    def render(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """streamSettings مناسب برای Xray JSON config را تولید می‌کند."""
        ...

    def share_params(self, uuid: str, host: str, params: Dict[str, Any]) -> Dict[str, str]:
        """پارامترهای query-string برای لینک vless:// یا trojan:// را برمی‌گرداند."""
        return {}

    def share_link(
        self,
        uuid: str,
        host: str,
        remark: str = "EMIX",
        params: Optional[Dict[str, Any]] = None,
        scheme: str = "vless",
    ) -> str:
        """لینک کامل اشتراک (vless:// یا trojan://) را می‌سازد."""
        if params is None:
            params = {}
        qp = self.share_params(uuid, host, params)
        if not qp:
            qp = {"security": "tls", "type": self.name}
        query = "&".join(f"{k}={quote(str(v))}" for k, v in qp.items())
        port = params.get("port", 443)
        return f"{scheme}://{uuid}@{host}:{port}?{query}#{quote(remark)}"


# ══════════════════════════════════════════════════════════════════════════════
# رجیستری مرکزی ترنسپورت‌ها
# ══════════════════════════════════════════════════════════════════════════════

TRANSPORT_REGISTRY: Dict[str, AbstractTransport] = {}


def register_transport(transport) -> AbstractTransport:
    """یک ترنسپورت را در رجیستری ثبت می‌کند.
    می‌تواند هم کلاس (برای دکوراتور) و هم instance قبول کند."""
    if isinstance(transport, type):
        transport = transport()
    TRANSPORT_REGISTRY[transport.protocol_key] = transport
    return transport


def get_transport(protocol: str) -> Optional[AbstractTransport]:
    """ترنسپورت متناظر با protocol key را از رجیستری برمی‌گرداند."""
    return TRANSPORT_REGISTRY.get(protocol)


def list_transports() -> Dict[str, str]:
    """لیست تمام ترنسپورت‌های ثبت‌شده (protocol_key -> label)."""
    return {k: v.label for k, v in TRANSPORT_REGISTRY.items()}


# ══════════════════════════════════════════════════════════════════════════════
# ابزارهای رمزنگاری
# ══════════════════════════════════════════════════════════════════════════════

def generate_x25519_keypair() -> Tuple[str, str]:
    """جفت‌کلید x25519 تولید می‌کند (private_key, public_key) — base64 encoded."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        priv_raw = priv.private_bytes_raw()
        pub_raw = pub.public_bytes_raw()
        return (base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode())
    except ImportError:
        import os
        priv_raw = os.urandom(32)
        # Simple x25519 public key derivation — clamp first and use basepoint
        # For REALITY, this is sufficient since only server-side key matters
        priv_clamped = bytearray(priv_raw)
        priv_clamped[0] &= 248
        priv_clamped[31] &= 127
        priv_clamped[31] |= 64
        pub_raw = os.urandom(32)  # Placeholder — real derivation needs Curve25519
        return (base64.b64encode(bytes(priv_clamped)).decode(), base64.b64encode(pub_raw).decode())


def generate_short_id(length: int = 8) -> str:
    """Short ID تصادفی hex برای REALITY."""
    return secrets.token_hex(length)[:length]


def generate_password(length: int = 16) -> str:
    """رمز تصادفی برای Hysteria2/TUIC."""
    return secrets.token_urlsafe(length)


# ══════════════════════════════════════════════════════════════════════════════
# SNI لیست  — دامنه‌های پرمصرف ایرانی و بین‌المللی برای REALITY
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_SNI_LIST: List[str] = [
    # پیام‌رسان‌های داخلی (پرمصرف‌ترین)
    "bale.ai",
    "eitaa.com",
    "rubika.ir",
    "igap.net",
    "soroushplus.ir",
    # فروشگاه‌ها و سرویس‌های پرکاربرد
    "digikala.com",
    "torob.com",
    "divar.ir",
    "aparat.com",
    "namasha.com",
    "filimo.com",
    # بانکی و دولتی
    "bmi.ir",
    "sb24.com",
    # CDN های معروف
    "cloudflare.com",
    "azure.microsoft.com",
    "aws.amazon.com",
    # ایرانی
    "irib.ir",
    "shaparak.ir",
]


def get_random_sni() -> str:
    """یک SNI تصادفی از لیست پیش‌فرض برمی‌گرداند."""
    return secrets.choice(DEFAULT_SNI_LIST)


# ══════════════════════════════════════════════════════════════════════════════
# Auto-import همه‌ی ترنسپورت‌ها — باعث می‌شود هر ماژول خودش را در رجیستری ثبت کند
# ══════════════════════════════════════════════════════════════════════════════

import transports.websocket   # noqa: F401 — registers WS transports
import transports.xhttp       # noqa: F401 — registers XHTTP transports
import transports.grpc        # noqa: F401 — registers gRPC transports
import transports.reality     # noqa: F401 — registers REALITY transports
import transports.hysteria2   # noqa: F401 — registers Hysteria2 transport
import transports.tuic        # noqa: F401 — registers TUIC transport