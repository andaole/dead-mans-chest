#!/usr/bin/env python3
"""Re-encrypt only the host area: role pages (Host, Co-host) and the full guide, one password.

Player packets are left exactly as they are, so nobody's open page moves.

Usage:
  python3 tools/build_host.py --host-password "PASSWORD" \
      --doc host "Host" /path/host.pdf --doc cohost "Co-host" /path/cohost.pdf \
      --doc guide "Full guide" "/path/Host & Co-host Guide.pdf"
The first --doc with id "guide" also gets a downloadable PDF.
"""
import argparse, base64, json, os, secrets, shutil, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_site import CHECK, DATA, b64, derive, norm, render, seal  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host-password", required=True)
    ap.add_argument("--doc", nargs=3, action="append", metavar=("ID", "TITLE", "PDF"), required=True)
    a = ap.parse_args()
    if len(norm(a.host_password)) < 6:
        sys.exit("Host password is too short")

    path = os.path.join(DATA, "index.json")
    index = json.load(open(path, encoding="utf-8"))
    old = index.get("host")

    secret = "HOST|" + norm(a.host_password)
    salt = secrets.token_bytes(16)
    key = derive(secret, salt)
    d = secrets.token_hex(8)
    os.makedirs(os.path.join(DATA, d))
    host = {"title": "Host & co-host", "salt": b64(salt), "check": b64(seal(key, CHECK)), "dir": d, "docs": []}
    for doc_id, title, pdf in a.doc:
        pages = render(pdf)
        os.makedirs(os.path.join(DATA, d, doc_id))
        for i, page in enumerate(pages, 1):
            with open(os.path.join(DATA, d, doc_id, f"{i}.bin"), "wb") as fh:
                fh.write(seal(key, page))
        entry = {"id": doc_id, "title": title, "pages": len(pages)}
        if doc_id == "guide":
            with open(os.path.join(DATA, d, "guide.bin"), "wb") as fh:
                fh.write(seal(key, open(pdf, "rb").read()))
            host["pdf"] = "guide.bin"
        host["docs"].append(entry)
        print(f"{title}: {len(pages)} pp")
    index["host"] = host
    json.dump(index, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    if old and old.get("dir") and old["dir"] != d:
        shutil.rmtree(os.path.join(DATA, old["dir"]), ignore_errors=True)


if __name__ == "__main__":
    main()
