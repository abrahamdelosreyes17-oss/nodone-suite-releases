"""Proof for sign_suite.py, with a throwaway key (never the release key).

  <python with cryptography> test_sign_suite.py
"""
import base64
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sign_suite as s  # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(("   PASS  " if ok else "   FAIL  ") + label + ("" if ok else f" — {detail}"))
    if not ok:
        FAILED.append(label)


def refused(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except s.Refused as exc:
        return str(exc)
    return None


tmp = Path(tempfile.mkdtemp(prefix="suite-test-"))
key = Ed25519PrivateKey.generate()
key_path = tmp / "test-key.pem"
key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                      serialization.PublicFormat.Raw)).decode()
installer = tmp / "NodOne-Setup-v3.4.0.exe"
installer.write_bytes(b"MZ" + b"\0" * 1000)
apps = tmp / "apps.json"


def write_apps(entries):
    apps.write_text(json.dumps({"apps": entries}), encoding="utf-8")


print("\nbuild: a good list")
write_apps([
    {"id": "nodone", "version": "3.4.0", "installer_file": str(installer), "notes": "New."},
    {"id": "gantt", "version": "1.11.0", "sha256": "A" * 64},
    {"id": "tala", "version": "1.0.0", "sha256": "b" * 64, "link": [1, 2]},
])
out = tmp / "out"
t0 = datetime(2026, 11, 2, 9, 0, 0, tzinfo=timezone.utc)
target, sig = s.build(apps, key_path, out, pub, now=t0)
body = target.read_bytes()
data = json.loads(body)
check("suite 1, published stamped", data["suite"] == 1 and data["published"] == "2026-11-02T09:00:00Z")
nod = data["apps"][0]
check("sha256 and size from the installer file", nod["size"] == 1002 and len(nod["sha256"]) == 64)
check("installer link built from the app's own repo",
      nod["installer"] == "https://github.com/abrahamdelosreyes17-oss/nodone-releases/releases/download/v3.4.0/NodOne-Setup-v3.4.0.exe")
check("sha256 kept lower case", data["apps"][1]["sha256"] == "a" * 64)
check("Tala's link numbers kept as data", data["apps"][2]["link"] == [1, 2])
check("written with LF only", b"\r" not in body and body.endswith(b"\n"))
check("verifies", s.verify(body, sig.read_bytes(), pub) is None)
check("one changed byte is refused",
      s.verify(body.replace(b"3.4.0", b"3.4.1", 1), sig.read_bytes(), pub) == "signature_invalid")
other = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
check("another key's check refuses it", s.verify(body, sig.read_bytes(), other) == "signature_invalid")
check("cli verify OK", s.main(["verify", str(target), "--pubkey", pub]) == 0)

print("\nbuild: what it refuses")
check("an older list than the one there",
      "newer" in (refused(s.build, apps, key_path, out, pub, now=t0 - timedelta(days=1)) or ""))
wrong_clock = tmp / "wrong-clock"
s.build(apps, key_path, wrong_clock, pub, now=t0 + timedelta(days=200))
check("a list there dated far ahead (a wrong clock) can be replaced",
      refused(s.build, apps, key_path, wrong_clock, pub, now=t0) is None)
check("a key that is not the release key",
      "not the release key" in (refused(s.build, apps, key_path, tmp / "o2", other) or ""))
for label, entry, word in [
    ("unknown app", {"id": "geo", "version": "1.0.0", "sha256": "a" * 64}, "unknown app"),
    ("bad version", {"id": "gantt", "version": "1.11", "sha256": "a" * 64}, "version"),
    ("installer on another repo", {"id": "gantt", "version": "1.11.0", "sha256": "a" * 64,
     "installer": "https://github.com/abrahamdelosreyes17-oss/nodone-releases/releases/download/v1.11.0/NodOneGantt-Setup-v1.11.0.exe"}, "installer must be"),
    ("no sha256", {"id": "gantt", "version": "1.11.0"}, "sha256"),
    ("unknown field", {"id": "gantt", "version": "1.11.0", "sha256": "a" * 64, "url": "x"}, "unknown fields"),
    ("installer_file with another name", {"id": "gantt", "version": "1.11.0", "installer_file": str(installer)}, "is not"),
]:
    write_apps([entry])
    check(label, word in (refused(s.build, apps, key_path, tmp / "o3", now=t0) or ""))
write_apps([{"id": "gantt", "version": "1.11.0", "sha256": "a" * 64}] * 2)
check("an app twice", "twice" in (refused(s.build, apps, key_path, tmp / "o4", now=t0) or ""))
inside = Path(s.__file__).resolve().parent / "inside-test-key.pem"
write_apps([{"id": "gantt", "version": "1.11.0", "sha256": "a" * 64}])
check("a key file inside the repo", "inside this repo" in (refused(s.build, apps, inside, tmp / "o5", now=t0) or ""))
check("the example apps file parses", isinstance(json.loads(
    (Path(s.__file__).resolve().parent / "apps.example.json").read_text(encoding="utf-8"))["apps"], list))

print(f"\n{'ALL PASS' if not FAILED else f'{len(FAILED)} FAILED: {FAILED}'}")
sys.exit(1 if FAILED else 0)
