"""
singboxbridge.py — پل sing-box برای پروتکل‌های QUIC پنل EMIX
═══════════════════════════════════════════════════════════
Hysteria2 و TUIC بر پایه‌ی QUIC هستند و هسته‌ی Xray آنها را سرو نمی‌کند.
این ماژول مثل xraybridge عمل می‌کند:

  ۱. باینری رسمی sing-box را (در صورت نبود) دانلود می‌کند
  ۲. گواهی self-signed می‌سازد تا کلاینت با insecure=1 وصل شود
  ۳. به‌ازای هر لینک hysteria2/tuic یک user در inbound متناظر می‌سازد
  ۴. پروسه را start/stop/restart می‌کند و وضعیت را گزارش می‌دهد

نکته: هیچ تغییری در رفتار پروتکل‌های اورجینال ایجاد نمی‌کند و فقط وقتی
لینک hysteria2/tuic وجود داشته باشد فعال می‌شود.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import shutil
import subprocess
import tarfile
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("EMIX.singboxbridge")

# ── مسیرها و تنظیمات ──────────────────────────────────────────────────────────
SB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sing-box")
SB_BIN = os.path.join(SB_DIR, "sing-box")
SB_CONFIG = os.path.join(SB_DIR, "config.json")
SB_CERT = os.path.join(SB_DIR, "cert.pem")
SB_KEY = os.path.join(SB_DIR, "key.pem")

HY2_PORT = int(os.environ.get("SINGBOX_HY2_PORT", "8444"))
TUIC_PORT = int(os.environ.get("SINGBOX_TUIC_PORT", "8445"))
SB_VERSION = os.environ.get("SINGBOX_VERSION", "1.10.7")

state: Dict[str, Any] = {
    "installed": False,
    "running": False,
    "pid": None,
    "inbounds": 0,
    "users": 0,
    "last_error": None,
    "started_at": None,
}

_process: Optional[asyncio.subprocess.Process] = None
_monotask: Optional[asyncio.Task] = None


# ══════════════════════════════════════════════════════════════════════════════
# گواهی TLS خودامضا برای inbound های QUIC
# ══════════════════════════════════════════════════════════════════════════════

def _cert_valid() -> bool:
    """گواهی موجود باید هر دو فایل داشته باشد و بیشتر از ۳۶۵ روز مانده باشد."""
    if not (os.path.isfile(SB_CERT) and os.path.isfile(SB_KEY)):
        return False
    try:
        age = time.time() - os.path.getmtime(SB_CERT)
        return age < 330 * 24 * 3600
    except OSError:
        return False


def _gen_cert_openssl(sni: str) -> bool:
    """ساخت گواهی با openssl CLI اگر روی سیستم موجود باشد."""
    exe = shutil.which("openssl")
    if not exe:
        return False
    try:
        subprocess.run(
            [exe, "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-keyout", SB_KEY, "-out", SB_CERT,
             "-days", "365", "-nodes",
             "-subj", f"/CN={sni}",
             "-addext", f"subjectAltName=DNS:{sni},DNS:example.com"],
            check=True, capture_output=True, timeout=30,
        )
        return True
    except Exception as exc:
        logger.warning(f"openssl cert failed: {exc}")
        return False


def _gen_cert_python(sni: str) -> bool:
    """ساخت گواهی با کتابخانه‌ی cryptography اگر نصب باشد."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime
        import ipaddress

        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, sni)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(sni), x509.DNSName("example.com")]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        with open(SB_KEY, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        with open(SB_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return True
    except Exception as exc:
        logger.warning(f"cryptography cert failed: {exc}")
        return False


def ensure_cert(sni: str = "example.com") -> bool:
    """در صورت نبود گواهی معتبر، یکی می‌سازد. موفقیت/شکست را برمی‌گرداند."""
    if _cert_valid():
        return True
    os.makedirs(SB_DIR, exist_ok=True)
    ok = _gen_cert_openssl(sni) or _gen_cert_python(sni)
    if not ok:
        state["last_error"] = "cannot generate TLS certificate (no openssl / cryptography)"
    return ok


# ══════════════════════════════════════════════════════════════════════════════
# نصب باینری sing-box
# ══════════════════════════════════════════════════════════════════════════════

def _download_url() -> str:
    machine = platform.machine().lower()
    arch = "arm64" if ("arm" in machine or "aarch64" in machine) else "amd64"
    return (
        f"https://github.com/SagerNet/sing-box/releases/download/"
        f"v{SB_VERSION}/sing-box-{SB_VERSION}-linux-{arch}.tar.gz"
    )


def is_installed() -> bool:
    return os.path.isfile(SB_BIN) and os.access(SB_BIN, os.X_OK)


async def install() -> dict:
    """دانلود و آماده‌سازی باینری sing-box."""
    global state
    if is_installed():
        state["installed"] = True
        return {"ok": True, "already": True}
    url = _download_url()
    tgz_path = os.path.join(SB_DIR, "sing-box.tar.gz")
    try:
        os.makedirs(SB_DIR, exist_ok=True)

        def _fetch():
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "EMIX-panel"})
            with urllib.request.urlopen(req, timeout=120) as resp, open(tgz_path, "wb") as f:
                shutil.copyfileobj(resp, f)

        await asyncio.get_event_loop().run_in_executor(None, _fetch)
        with tarfile.open(tgz_path, "r:gz") as tf:
            member = next(
                m for m in tf.getmembers()
                if m.isfile() and m.name.endswith("/sing-box")
            )
            member.name = "sing-box"
            tf.extract(member, SB_DIR)
        os.chmod(SB_BIN, 0o755)
        os.remove(tgz_path)
        state["installed"] = True
        state["last_error"] = None
        logger.info(f"sing-box bridge: باینری نصب شد ({url})")
        return {"ok": True}
    except Exception as exc:
        state["last_error"] = f"install failed: {exc}"
        logger.error(f"sing-box bridge: خطا در نصب: {exc}")
        return {"ok": False, "error": str(exc)}


# ══════════════════════════════════════════════════════════════════════════════
# ساخت کانفیگ از روی لینک‌های پنل
# ══════════════════════════════════════════════════════════════════════════════

def build_config(links: List[dict]) -> Optional[dict]:
    """کانفیگ سرور sing-box را از لینک‌های hysteria2/tuic پنل می‌سازد.

    هر لینک فعال یک user در inbound متناظر می‌شود. اگر هیچ لینکی نباشد
    None برمی‌گرداند.
    """
    hy2_users: List[dict] = []
    obfs_password: Optional[str] = None
    tuic_users: List[dict] = []

    for link in links:
        proto = link.get("protocol")
        if not link.get("active", True):
            continue
        uid = link.get("uuid")
        if not uid:
            continue
        label = (link.get("label") or "user")[:20]
        if proto == "hysteria2":
            pw = link.get("hy2_password")
            if pw:
                hy2_users.append({"name": f"{label}-{uid[:8]}", "password": pw})
                opw = link.get("hy2_obfs_password")
                if opw and not obfs_password:
                    obfs_password = opw
        elif proto == "tuic":
            pw = link.get("tuic_password")
            if pw:
                tuic_users.append({
                    "name": f"{label}-{uid[:8]}",
                    "uuid": uid,
                    "password": pw,
                })

    inbounds: List[dict] = []

    if hy2_users:
        inbound: Dict[str, Any] = {
            "type": "hysteria2",
            "tag": "emix-hy2-in",
            "listen": "::",
            "listen_port": HY2_PORT,
            "users": hy2_users,
            "ignore_client_bandwidth": False,
            "tls": {
                "enabled": True,
                "alpn": ["h3"],
                "certificate_path": SB_CERT,
                "key_path": SB_KEY,
            },
        }
        if obfs_password:
            inbound["obfs"] = {"type": "salamander", "password": obfs_password}
        inbounds.append(inbound)

    if tuic_users:
        inbounds.append({
            "type": "tuic",
            "tag": "emix-tuic-in",
            "listen": "::",
            "listen_port": TUIC_PORT,
            "users": tuic_users,
            "congestion_control": "bbr",
            "tls": {
                "enabled": True,
                "alpn": ["h3"],
                "certificate_path": SB_CERT,
                "key_path": SB_KEY,
            },
        })

    if not inbounds:
        return None

    return {
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }


# ══════════════════════════════════════════════════════════════════════════════
# مدیریت پروسه
# ══════════════════════════════════════════════════════════════════════════════

async def stop():
    """توقف پروسه‌ی sing-box در صورت اجرا."""
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
        l.get("protocol") in ("hysteria2", "tuic")
        for l in links if l.get("active", True)
    ):
        await stop()
        state["inbounds"] = 0
        state["users"] = 0
        return {"ok": True, "stopped": True, "reason": "no quic links"}

    if not is_installed():
        result = await install()
        if not result.get("ok"):
            return result

    # گواهی: از SNI اولین لینک REALITY یا پیش‌فرض استفاده کن
    sni = "example.com"
    for l in links:
        rp = l.get("reality_params") or {}
        if rp.get("server_name"):
            sni = rp["server_name"]
            break
    if not ensure_cert(sni):
        return {"ok": False, "error": state.get("last_error")}

    config = build_config(links)
    if config is None:
        await stop()
        return {"ok": True, "stopped": True, "reason": "empty config"}

    n_users = sum(len(i["users"]) for i in config["inbounds"])

    with open(SB_CONFIG, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # restart
    await stop()
    try:
        _process = await asyncio.create_subprocess_exec(
            SB_BIN, "run", "-c", SB_CONFIG,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except Exception as exc:
        state["last_error"] = f"spawn failed: {exc}"
        return {"ok": False, "error": str(exc)}

    state.update({
        "running": True,
        "pid": _process.pid,
        "inbounds": len(config["inbounds"]),
        "users": n_users,
        "last_error": None,
        "started_at": time.time(),
    })
    logger.info(f"sing-box bridge: started pid={_process.pid} "
                f"(hy2_port={HY2_PORT}, tuic_port={TUIC_PORT}, users={n_users})")

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
            logger.warning(f"sing-box bridge: پروسه خارج شد — {state['last_error']}")

    global _monotask
    if _monotask and not _monotask.done():
        _monotask.cancel()
    _monotask = asyncio.get_event_loop().create_task(_monitor(_process))

    return {"ok": True, "running": True, "pid": _process.pid,
            "inbounds": len(config["inbounds"]), "users": n_users}


def status() -> dict:
    s = dict(state)
    s["installed"] = is_installed()
    s["binary"] = SB_BIN if is_installed() else None
    s["cert_ready"] = _cert_valid()
    s["ports"] = {"hysteria2": HY2_PORT, "tuic": TUIC_PORT}
    return s
