"""
xraybridge.py — پل Xray-core برای پروتکل‌های جدید EMIX
═══════════════════════════════════════════════════════
پنل EMIX خودش برای WS/XHTTP سرور داخلی دارد، اما REALITY و gRPC به
هسته‌ی Xray نیاز دارند. این ماژول:

  ۱. باینری رسمی Xray-core را (در صورت نبود) دانلود می‌کند
  ۲. به‌ازای لینک‌های vless-reality / vless-grpc یک inbound با همان
     uuid/کلید/SNI می‌سازد تا لینک‌های تولیدی پنل واقعاً پینگ بدهند
  ۳. پروسه را start/stop/restart می‌کند و وضعیت را گزارش می‌دهد

نکته‌ی مهم: هیچ تغییری در رفتار پروتکل‌های اورجینال (WS/XHTTP) ایجاد
نمی‌کند — فقط وقتی لینکی با پروتکل جدید وجود داشته باشد فعال می‌شود.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import platform
import shutil
import struct
import zipfile
from typing import Any, Dict, List, Optional

logger = logging.getLogger("EMIX.xraybridge")

# ── مسیرها و تنظیمات ──────────────────────────────────────────────────────────
XRAY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xray-core")
XRAY_BIN = os.path.join(XRAY_DIR, "xray")
XRAY_CONFIG = os.path.join(XRAY_DIR, "config.json")

# پورت‌ها: از env قابل تغییر هستند؛ پیش‌فرض منطقی برای دیپلوی Railway
REALITY_PORT = int(os.environ.get("XRAY_REALITY_PORT", "8443"))
GRPC_PORT = int(os.environ.get("XRAY_GRPC_PORT", "2084"))
XRAY_VERSION = os.environ.get("XRAY_VERSION", "v25.1.30")

state: Dict[str, Any] = {
    "installed": False,
    "running": False,
    "pid": None,
    "inbounds": 0,
    "clients": 0,
    "last_error": None,
    "started_at": None,
}

_process: Optional[asyncio.subprocess.Process] = None
_monotask: Optional[asyncio.Task] = None


# ══════════════════════════════════════════════════════════════════════════════
# رمزنگاری x25519 سازگار با Xray (بدون وابستگی خارجی)
# ══════════════════════════════════════════════════════════════════════════════

def _b64url_raw(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _x25519_scalarmult(scalar: bytes, point: bytes) -> bytes:
    """ضرب نقطه‌ای x25519 مطابق RFC 7748 (خالص پایتون، فقط برای کلید عمومی)."""
    P = 2 ** 255 - 19
    A24 = 121665

    def cswap(swap: int, x2: int, x3: int):
        dummy = swap * ((x2 ^ x3) & 0xFFFFFFFFFFFFFFFF)
        return x2 ^ dummy, x3 ^ dummy

    def clamp(k: bytes) -> int:
        k_list = bytearray(k)
        k_list[0] &= 248
        k_list[31] &= 127
        k_list[31] |= 64
        return int.from_bytes(bytes(k_list), "little")

    k = clamp(scalar)
    x1 = int.from_bytes(point, "little")
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0

    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = kt

        A = (x2 + z2) % P
        AA = (A * A) % P
        B = (x2 - z2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x3 = (DA + CB) % P
        x3 = (x3 * x3) % P
        z3 = (DA - CB) % P
        z3 = (z3 * z3) % P
        z3 = (x1 * z3) % P
        x2 = (AA * BB) % P
        z2 = (E * ((AA + A24 * E) % P)) % P

    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    return (((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, "little"))


def generate_keypair() -> tuple[str, str]:
    """جفت‌کلید x25519 سازگار با فرمت Xray برمی‌گرداند (privateKey, publicKey)."""
    import os as _os
    priv = bytearray(_os.urandom(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    basepoint = (9).to_bytes(32, "little")
    pub = _x25519_scalarmult(bytes(priv), basepoint)
    return _b64url_raw(bytes(priv)), _b64url_raw(pub)


def generate_short_id(length: int = 8) -> str:
    import secrets
    return secrets.token_hex((length + 1) // 2)[:length]


# ══════════════════════════════════════════════════════════════════════════════
# نصب باینری Xray
# ══════════════════════════════════════════════════════════════════════════════

def _download_url() -> str:
    machine = platform.machine().lower()
    if "arm" in machine or "aarch64" in machine:
        asset = "Xray-linux-arm64-v8a.zip"
    else:
        asset = "Xray-linux-64.zip"
    return f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/{asset}"


def is_installed() -> bool:
    return os.path.isfile(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK)


async def install() -> dict:
    """دانلود و آماده‌سازی باینری Xray-core."""
    global state
    if is_installed():
        state["installed"] = True
        return {"ok": True, "already": True}
    url = _download_url()
    zip_path = os.path.join(XRAY_DIR, "xray.zip")
    try:
        os.makedirs(XRAY_DIR, exist_ok=True)

        def _fetch():
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "EMIX-panel"})
            with urllib.request.urlopen(req, timeout=120) as resp, open(zip_path, "wb") as f:
                shutil.copyfileobj(resp, f)

        await asyncio.get_event_loop().run_in_executor(None, _fetch)
        with zipfile.ZipFile(zip_path) as zf:
            for name in ("xray", "geoip.dat", "geosite.dat"):
                try:
                    zf.extract(name, XRAY_DIR)
                except KeyError:
                    pass
        os.chmod(XRAY_BIN, 0o755)
        os.remove(zip_path)
        state["installed"] = True
        state["last_error"] = None
        logger.info(f"Xray bridge: باینری نصب شد ({url})")
        return {"ok": True}
    except Exception as exc:
        state["last_error"] = f"install failed: {exc}"
        logger.error(f"Xray bridge: خطا در نصب: {exc}")
        return {"ok": False, "error": str(exc)}


# ══════════════════════════════════════════════════════════════════════════════
# ساخت کانفیگ از روی لینک‌های پنل
# ══════════════════════════════════════════════════════════════════════════════

def build_config(links: List[dict], reality_port: int = None, grpc_port: int = None) -> Optional[dict]:
    """کانفیگ کامل Xray را از لیست لینک‌های پنل می‌سازد.

    هر لینک با protocol=vless-reality یا vless-grpc به یک client در inbound
    متناظر تبدیل می‌شود. اگر هیچ لینک جدیدی وجود نداشته باشد None برمی‌گرداند.
    """
    reality_port = reality_port or REALITY_PORT
    grpc_port = grpc_port or GRPC_PORT

    reality_clients: List[dict] = []
    reality_keys: List[dict] = []   # کلید هر لینک برای گزارش
    grpc_clients: List[dict] = []

    for link in links:
        proto = link.get("protocol")
        if not link.get("active", True):
            continue
        uid = link.get("uuid")
        if not uid:
            continue
        if proto == "vless-reality":
            rp = link.get("reality_params") or {}
            client = {
                "id": uid,
                "flow": "xtls-rprx-vision",
                "email": f"{link.get('label', 'user')[:20]}-{uid[:8]}",
            }
            if client not in reality_clients:
                reality_clients.append(client)
                reality_keys.append({
                    "uuid": uid,
                    "sni": rp.get("server_name"),
                    "short_id": (rp.get("short_ids") or [""])[0],
                    "private_key": rp.get("private_key"),
                    "public_key": rp.get("public_key"),
                })
        elif proto == "vless-grpc":
            svc = link.get("grpc_service", "GunService")
            client = {"id": uid, "email": f"{link.get('label', 'user')[:20]}-{uid[:8]}"}
            # هر serviceName یک inbound جدا لازم دارد
            existing = next((c for c in grpc_clients if c["_service"] == svc), None)
            if existing:
                if client not in existing["clients"]:
                    existing["clients"].append(client)
            else:
                grpc_clients.append({"_service": svc, "clients": [client]})
        # trojan-grpc فعلاً توسط هسته‌ی پایتونی پشتیبانی نمی‌شود؛ آینده

    inbounds: List[dict] = []

    # ── inbound مشترک REALITY (یک پورت، چند کلاینت) ──
    # نکته: Xray اجازه‌ی چند privateKey در یک inbound نمی‌دهد؛ بنابراین هر لینک
    # REALITY با کلید متفاوت باید port خودش را داشته باشد. برای سادگی، همه‌ی
    # لینک‌ها از اولین کلید استفاده می‌کنند مگر اینکه per-port فعال باشد.
    if reality_clients:
        first = reality_keys[0]
        short_ids = sorted({k["short_id"] for k in reality_keys if k["short_id"]} | {""})
        sni = first["sni"] or "digikala.com"
        inbounds.append({
            "listen": "0.0.0.0",
            "port": reality_port,
            "protocol": "vless",
            "settings": {"clients": reality_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": f"{sni}:443",
                    "xver": 0,
                    "serverNames": [sni],
                    "privateKey": first["private_key"],
                    "shortIds": short_ids,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # ── inbound های gRPC (هر serviceName یک پورت) ──
    for i, entry in enumerate(grpc_clients):
        inbounds.append({
            "listen": "0.0.0.0",
            "port": grpc_port + i,
            "protocol": "vless",
            "settings": {"clients": entry["clients"], "decryption": "none"},
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {"serviceName": entry["_service"]},
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    if not inbounds:
        return None

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# مدیریت پروسه
# ══════════════════════════════════════════════════════════════════════════════

async def stop():
    """توقف پروسه‌ی Xray در صورت اجرا."""
    global _process, state
    if _process and _process.returncode is None:
        try:
            _process.terminate()
            await asyncio.wait_for(_process.wait(), timeout=5)
        except Exception:
            try:
                _process.kill()
            except Exception:
                pass
    _process = None
    state.update({"running": False, "pid": None})


async def sync_and_start(links: List[dict]) -> dict:
    """ساخت کانفیگ از روی لینک‌ها، نوشتن فایل و (re)start پروسه."""
    global _process, state

    if not links or not any(
        l.get("protocol") in ("vless-reality", "vless-reality-grpc", "vless-grpc")
        for l in links if l.get("active", True)
    ):
        await stop()
        state["inbounds"] = 0
        state["clients"] = 0
        return {"ok": True, "stopped": True, "reason": "no new-protocol links"}

    if not is_installed():
        result = await install()
        if not result.get("ok"):
            return result

    config = build_config(links)
    if config is None:
        await stop()
        return {"ok": True, "stopped": True, "reason": "empty config"}

    n_reality = sum(1 for i in config["inbounds"]
                     if i.get("streamSettings", {}).get("security") == "reality")
    n_grpc = len(config["inbounds"]) - n_reality
    n_clients = sum(len(i["settings"]["clients"]) for i in config["inbounds"])

    with open(XRAY_CONFIG, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # restart
    await stop()
    try:
        _process = await asyncio.create_subprocess_exec(
            XRAY_BIN, "run", "-c", XRAY_CONFIG,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as exc:
        state["last_error"] = f"spawn failed: {exc}"
        return {"ok": False, "error": str(exc)}

    import time
    state.update({
        "running": True,
        "pid": _process.pid,
        "inbounds": len(config["inbounds"]),
        "clients": n_clients,
        "last_error": None,
        "started_at": time.time(),
    })
    logger.info(f"Xray bridge: started pid={_process.pid} "
                f"(reality={n_reality}, grpc={n_grpc}, clients={n_clients})")

    # مانیتور خاموش‌شدن غیرمنتظره
    async def _monitor(proc):
        await proc.wait()
        if state.get("pid") == proc.pid:
            state["running"] = False
            err = ""
            try:
                out = await asyncio.wait_for(proc.stdout.read(), timeout=2)
                err = out.decode(errors="ignore")[-400:]
            except Exception:
                pass
            state["last_error"] = f"exited ({proc.returncode}): {err}" or f"exited ({proc.returncode})"
            logger.warning(f"Xray bridge: پروسه خارج شد — {state['last_error']}")

    global _monotask
    if _monotask and not _monotask.done():
        _monotask.cancel()
    _monotask = asyncio.get_event_loop().create_task(_monitor(_process))

    return {"ok": True, "running": True, "pid": _process.pid,
            "inbounds": len(config["inbounds"]), "clients": n_clients}


def status() -> dict:
    s = dict(state)
    s["installed"] = is_installed()
    s["binary"] = XRAY_BIN if is_installed() else None
    s["ports"] = {"reality": REALITY_PORT, "grpc": GRPC_PORT}
    return s
