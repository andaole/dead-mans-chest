#!/usr/bin/env python3
"""Re-encrypt only the Host & Co-host Guide (new PDF and/or new password).

Player packets are left exactly as they are, so nobody's open page moves.

Usage:
  python3 tools/build_host.py --host-guide "/path/to/Guide.pdf" --host-password "PASSWORD"
"""
import argparse, base64, json, os, shutil, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_site import DATA, derive, norm, render, seal, section  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-guide", required=True)
    ap.add_argument("--host-password", required=True)
    a = ap.parse_args()
    if len(norm(a.host_password)) < 6:
        sys.exit("Host password is too short")

    path = os.path.join(DATA, "index.json")
    index = json.load(open(path, encoding="utf-8"))
    old = index.get("host")

    secret = "HOST|" + norm(a.host_password)
    host = section(render(a.host_guide), secret, "Host & Co-host Guide")
    salt = base64.b64decode(host["salt"])
    with open(os.path.join(DATA, host["dir"], "guide.bin"), "wb") as fh:
        fh.write(seal(derive(secret, salt), open(a.host_guide, "rb").read()))
    host["pdf"] = "guide.bin"
    index["host"] = host
    json.dump(index, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    if old and old.get("dir") and old["dir"] != host["dir"]:
        shutil.rmtree(os.path.join(DATA, old["dir"]), ignore_errors=True)
    print(f"host guide {host['pages']} pp in data/{host['dir']}")


if __name__ == "__main__":
    main()
