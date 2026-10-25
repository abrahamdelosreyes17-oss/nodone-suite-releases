"""Build, sign and check nodone-suite's suite.json (phase 8).

suite.json lists every app with its newest version, the link to that
version's installer (on the app's own releases repo) and the installer's
SHA-256. suite.json.sig next to it is the Ed25519 signature (base64) over
the file's exact bytes, made with the SAME release key and scheme as
NodOne's releases.json (nodone/packaging/windows/release_signing.py). NodOne
and Gantt trust the list only when that signature verifies against the
public key built into them.

  python sign_suite.py build <apps.json> --key <private key .pem> [--out <folder>] [--pubkey <b64>]
  python sign_suite.py verify <suite.json> --pubkey <b64>

build   reads <apps.json> (see apps.example.json), checks every entry the way
        the apps will, fills in sha256 and size from a local installer file
        when "installer_file" is given, stamps "published" (UTC now), and
        writes <out>/suite.json and <out>/suite.json.sig (default: this
        folder). It refuses a list older than the suite.json already there
        (the apps refuse it too), a key file inside this folder, and a key
        whose public half is not --pubkey when --pubkey is given.
verify  checks <suite.json>.sig against --pubkey and the list's shape.

Needs `cryptography` (requirements.txt; the same pin as NodOne). The key is
only read from the path given; nothing here prints it.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
FORMAT = 1
OWNER = "abrahamdelosreyes17-oss"
# Each app's own releases repo and installer name (part 6 of the suite review).
APPS = {
    "nodone": ("nodone-releases", "NodOne-Setup-v{v}.exe"),
    "gantt": ("nodone-gantt-releases", "NodOneGantt-Setup-v{v}.exe"),
    "tala": ("nodone-tala-releases", "NodOneTala-Setup-v{v}.exe"),
    "suite": ("nodone-suite-releases", "NodOneSuite-Setup-v{v}.exe"),
    "tools": ("nodone-tools-releases", "NodOneTools-Setup-v{v}.exe"),
    # Coordinate Converter 2.6.1 becomes this app: same releases repo, same installer name, the old AppId.
    "coordinates": ("coordinate-converter-releases", "CoordinateConverter-Setup-v{v}.exe"),
}
VERSION_RE = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
PUBLISHED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
APP_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
# Fields an app entry may carry, as the apps read them.
FIELDS = ("id", "version", "installer", "sha256", "size", "notes", "app_id", "link", "needs_link")


class Refused(Exception):
    pass


def installer_url(app_id: str, version: str) -> str:
    repo, name = APPS[app_id]
    return f"https://github.com/{OWNER}/{repo}/releases/download/v{version}/{name.format(v=version)}"


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
            size += len(block)
    return h.hexdigest(), size


def check_entry(app: object, base: Path) -> dict:
    """One app entry as it will be published, or Refused."""
    if not isinstance(app, dict):
        raise Refused("an app entry is not an object")
    app = dict(app)
    app_id = app.get("id")
    if app_id not in APPS:
        raise Refused(f"unknown app id {app_id!r} (known: {', '.join(APPS)})")
    version = app.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise Refused(f"{app_id}: version must look like 1.2.3, not {version!r}")
    expected_url = installer_url(app_id, version)
    url = app.get("installer") or expected_url
    if url != expected_url:
        raise Refused(f"{app_id}: installer must be {expected_url}")
    parts = urlsplit(url)
    if parts.query or parts.fragment or "%" in url or ".." in url:
        raise Refused(f"{app_id}: installer link has extra parts")
    app["installer"] = url
    local = app.pop("installer_file", None)
    if local:
        path = (base / local) if not Path(local).is_absolute() else Path(local)
        if path.name != url.rsplit("/", 1)[-1]:
            raise Refused(f"{app_id}: installer_file {path.name} is not {url.rsplit('/', 1)[-1]}")
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                raise Refused(f"{app_id}: {path.name} is not a Windows program")
        digest, size = _sha256_file(path)
        if app.get("sha256") and app["sha256"].lower() != digest:
            raise Refused(f"{app_id}: sha256 given differs from {path.name}'s")
        app["sha256"], app["size"] = digest, size
    sha = app.get("sha256")
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha.lower()):
        raise Refused(f"{app_id}: sha256 must be 64 hex characters (or give installer_file)")
    app["sha256"] = sha.lower()
    size = app.get("size")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size <= 0):
        raise Refused(f"{app_id}: size must be a positive number of bytes")
    notes = app.get("notes")
    if notes is not None and (not isinstance(notes, str) or len(notes) > 4000):
        raise Refused(f"{app_id}: notes must be text of at most 4000 characters")
    extra = sorted(set(app) - set(FIELDS))
    if extra:
        raise Refused(f"{app_id}: unknown fields {extra}")
    return {k: app[k] for k in FIELDS if k in app}


def check_list(data: object) -> dict:
    """The shape every app checks (NodOne's parse_suite, Gantt's too)."""
    if not isinstance(data, dict) or data.get("suite") != FORMAT:
        raise Refused(f'"suite" must be {FORMAT}')
    if not isinstance(data.get("published"), str) or not PUBLISHED_RE.fullmatch(data["published"]):
        raise Refused('"published" must be a UTC time like 2026-11-02T09:00:00Z')
    apps = data.get("apps")
    if not isinstance(apps, list) or not apps:
        raise Refused('"apps" must be a list of apps')
    ids = [a.get("id") if isinstance(a, dict) else None for a in apps]
    if not all(isinstance(i, str) and APP_ID_RE.fullmatch(i) for i in ids):
        raise Refused("every app needs an id")
    if len(set(ids)) != len(ids):
        raise Refused("an app is listed twice")
    return data


def _pub_b64(key) -> str:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _load_key(path: Path):
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415

    try:
        path.resolve().relative_to(HERE)
        raise Refused(f"{path} is inside this repo. Keep the signing key outside it.")
    except ValueError:
        pass
    if not path.is_file():
        raise Refused(f"no key file at {path}")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise Refused(f"{path} is not an Ed25519 private key")
    return key


def verify(body: bytes, sig_text: bytes, pubkey_b64: str) -> str | None:
    """None when the signature is valid and the list has the right shape,
    else a short reason. The same check as NodOne's updater."""
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: PLC0415

    try:
        key = base64.b64decode(pubkey_b64, validate=True)
        sig = base64.b64decode(bytes(sig_text).strip(), validate=True)
    except Exception:  # noqa: BLE001
        return "not_base64"
    if len(key) != 32 or len(sig) != 64:
        return "wrong_length"
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, bytes(body))
    except InvalidSignature:
        return "signature_invalid"
    try:
        check_list(json.loads(bytes(body).decode("utf-8")))
    except (Refused, ValueError) as exc:
        return f"bad_list: {exc}"
    return None


def build(apps_file: Path, key_path: Path, out: Path, pubkey: str | None = None,
          now: datetime | None = None) -> tuple[Path, Path]:
    source = json.loads(Path(apps_file).read_text(encoding="utf-8"))
    if not isinstance(source, dict) or not isinstance(source.get("apps"), list):
        raise Refused('apps file needs an "apps" list')
    apps = [check_entry(a, Path(apps_file).resolve().parent) for a in source["apps"]]
    published = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = check_list({"suite": FORMAT, "published": published, "apps": apps})
    out = Path(out)
    target, sig_path = out / "suite.json", out / "suite.json.sig"
    if target.is_file():
        try:
            before = json.loads(target.read_text(encoding="utf-8")).get("published", "")
        except ValueError:
            before = ""
        if isinstance(before, str) and before > published:
            # A list dated more than a day ahead was signed with a wrong clock:
            # the apps don't let it refuse later lists, so replacing it is the way out.
            ahead = (now or datetime.now(timezone.utc)) + timedelta(days=1)
            if before <= ahead.strftime("%Y-%m-%dT%H:%M:%SZ"):
                raise Refused(f"the suite.json there is newer ({before}); the apps would refuse this one")
            print(f"note: the suite.json there is dated {before}, ahead of this clock; replacing it")
    key = _load_key(Path(key_path))
    if pubkey is not None and _pub_b64(key) != pubkey:
        raise Refused("this key is not the release key (its public half differs from --pubkey)")
    body = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    sig = base64.b64encode(key.sign(body)) + b"\n"
    reason = verify(body, sig, _pub_b64(key))
    if reason is not None:
        raise Refused(f"the new signature does not verify ({reason})")
    out.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    sig_path.write_bytes(sig)
    return target, sig_path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build, sign and check suite.json.")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("apps", type=Path)
    b.add_argument("--key", type=Path, required=True)
    b.add_argument("--out", type=Path, default=HERE)
    b.add_argument("--pubkey", default=None)
    v = sub.add_parser("verify")
    v.add_argument("suite", type=Path)
    v.add_argument("--pubkey", required=True)
    a = p.parse_args(argv)
    try:
        if a.cmd == "build":
            target, sig = build(a.apps, a.key, a.out, a.pubkey)
            print(f"written: {target}")
            print(f"written: {sig}")
            return 0
        body = a.suite.read_bytes()
        sig_file = a.suite.with_name(a.suite.name + ".sig")
        if not sig_file.is_file():
            print(f"FAIL: {sig_file} is missing")
            return 3
        reason = verify(body, sig_file.read_bytes(), a.pubkey)
        if reason:
            print(f"FAIL: {reason}")
            return 3
        print("OK: signature valid and the list is well formed")
        return 0
    except Refused as exc:
        print(f"REFUSED: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
