# nodone-suite

The one list of Andrea's apps. It lists and points; it holds no source code, and each app's installer stays on
that app's own releases page.

| File | What it is |
| --- | --- |
| `suite.json` | Every app's newest version, the link to that version's installer, its SHA-256 and size |
| `suite.json.sig` | The Ed25519 signature over `suite.json`'s exact bytes (base64), made with the release key |
| `sign_suite.py` | Builds, signs and checks the two files above |
| `apps.example.json` | What `sign_suite.py build` reads |
| `test_sign_suite.py` | Its proof, with a throwaway key |

## How the apps read it

NodOne (from 3.4.0) and Gantt (from 1.11.0) fetch
`https://raw.githubusercontent.com/abrahamdelosreyes17-oss/nodone-suite/main/suite.json` and `.sig` as plain files
(no GitHub API, which allows only 60 checks an hour per network). They:

1. trust the list only when the signature verifies against the release key built into them (the same key and
   scheme as NodOne's `releases.json`);
2. keep the last good copy, and use it when the hub can't be reached ("busy" is never an error);
3. refuse a list that is badly signed, malformed, or older than their kept copy (a kept copy dated more than a
   day ahead of their clock is not used for this, so a list signed with a wrong clock can be replaced);
4. take the installer's SHA-256 from the signed list and refuse a download that doesn't match;
5. accept only an installer link on that app's own releases repo.

The old lists stay alive: every NodOne release still goes into `nodone-releases` (with its signed `releases.json`)
and every Gantt release onto `nodone-gantt-releases`, so an old copy anywhere keeps updating.

## The format

```json
{
  "suite": 1,
  "published": "2026-11-02T09:00:00Z",
  "apps": [
    { "id": "tala", "version": "1.0.0", "link": [1, 2], "installer": "https://github.com/abrahamdelosreyes17-oss/nodone-tala-releases/releases/download/v1.0.0/NodOneTala-Setup-v1.0.0.exe", "sha256": "…", "size": 0 },
    { "id": "nodone", "version": "3.4.0", "needs_link": 2, "app_id": "{9A2D7E4F-3B1C-4D8A-AE52-F0C8D1B6E923}", "installer": "https://github.com/abrahamdelosreyes17-oss/nodone-releases/releases/download/v3.4.0/NodOne-Setup-v3.4.0.exe", "sha256": "…", "size": 0, "notes": "Tala opens on the chat you were in." },
    { "id": "gantt", "version": "1.11.0", "needs_link": 2, "app_id": "{F7BEB33D-B7EC-4129-A1C2-976E9BB6EA6D}", "installer": "https://github.com/abrahamdelosreyes17-oss/nodone-gantt-releases/releases/download/v1.11.0/NodOneGantt-Setup-v1.11.0.exe", "sha256": "…", "size": 0 }
  ]
}
```

`id` is one of `nodone`, `gantt`, `tala`, `suite`. `link` (Tala) and `needs_link` (the apps) are the link
versions of rule 4; NodOne and Gantt only carry them for now. `app_id` is the app's permanent Windows ID.

## Publishing a new list (Abraham)

From this folder, with any Python that has `cryptography` (NodOne's backend venv has it):

```powershell
& "D:\Andrea\Individual Apps\nodone\backend\.venv\Scripts\python.exe" sign_suite.py build apps.json --key "$env:USERPROFILE\.nodone-release\release-signing-key.pem" --pubkey bsvvo2LgaqsRPDyqUtwYvc8UAy3FQCUHQQ7cOEnasMw=
& "D:\Andrea\Individual Apps\nodone\backend\.venv\Scripts\python.exe" sign_suite.py verify suite.json --pubkey bsvvo2LgaqsRPDyqUtwYvc8UAy3FQCUHQQ7cOEnasMw=
git add suite.json suite.json.sig
git commit -m "suite: NodOne 3.4.0, Gantt 1.11.0"
git push
```

`--pubkey` is the public half built into the apps (NodOne's `backend/app/updater.py`, `_RELEASE_PUBKEY_B64`): the
build stops if the key is a different one. Each installer must already be on its own releases page before the list
that points to it is pushed. `.gitattributes` keeps both files byte for byte; a changed line ending would break the
signature.

## Setting it up (once, Abraham)

1. On GitHub, create the public repo `abrahamdelosreyes17-oss/nodone-suite` (no README, no licence: empty).
2. Here: `git remote add origin https://github.com/abrahamdelosreyes17-oss/nodone-suite.git`, then build the first
   list as above and `git push -u origin main`.
3. The signing key stays where it is today, outside every repo
   (`%USERPROFILE%\.nodone-release\release-signing-key.pem`, backed up off the laptop). Nothing new to make.
