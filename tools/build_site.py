#!/usr/bin/env python3
"""Build the encrypted packet viewer for A Dead Man's Chest.

Every packet page is rendered to WebP and encrypted with AES-256-GCM.
The key comes from PBKDF2-SHA256 over the player's personal code
(plus the party word for the envelope, when the envelope is locked).
Nothing readable about a player's packet is committed to the repo.

Usage:
  python3 tools/build_site.py --packets "/path/to/Packets" \
      --codes ../codes.json [--party-word KRAKEN-RUM-7342 | --no-envelope-lock]

  --packets  folder holding 1_Send_ahead/ and 2_Envelopes/ (files start "NN ")
  --codes    JSON file {"01": "01", ...}: each player's password (their packet number).

Needs: poppler-utils (pdftoppm), Pillow, cryptography.
"""
import argparse, base64, glob, io, json, os, re, secrets, shutil, subprocess, sys, tempfile

from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")

ITER = 400_000
CACHE = os.path.join(ROOT, ".render_cache")   # plaintext page renders (gitignored)
CHECK = b"ahoy-matey"
MAX_W = 1275          # 150 dpi letter width
QUALITY = 72
# Envelope pages players should NOT see (1-based). Page 1 of every envelope is the
# host's "PUT IN THIS ENVELOPE" assembly sheet; Ortega's page 5 is host slips for others.
ENV_SKIP_ALL = {1}
ENV_SKIP = {"17": {5}}


def norm(s):
    s = unicodedata.normalize("NFD", s or "")
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"[^A-Z0-9]", "", s.upper())


def derive(secret, salt):
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, ITER, 32)


def seal(key, data):
    iv = secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, data, None)


def b64(b):
    return base64.b64encode(b).decode()


def find_pdf(folder, num):
    hits = sorted(glob.glob(os.path.join(folder, f"{num} *.pdf")))
    if len(hits) != 1:
        sys.exit(f"Expected exactly one PDF starting '{num} ' in {folder}, found {hits}")
    return hits[0]


def render(pdf, skip=()):
    """Return list of WebP bytes, one per page (minus 1-based pages in skip)."""
    h = hashlib.sha256(open(pdf, "rb").read()).hexdigest()[:20]
    cdir = os.path.join(CACHE, h)
    n_pages = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", pdf], capture_output=True, text=True).stdout).group(1))
    want = [n for n in range(1, n_pages + 1) if n not in skip]
    if all(os.path.exists(os.path.join(cdir, f"p{n}.webp")) for n in want):
        return [open(os.path.join(cdir, f"p{n}.webp"), "rb").read() for n in want]
    os.makedirs(cdir, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["pdftoppm", "-r", "150", "-png", pdf, os.path.join(td, "p")], check=True)
        out = []
        files = sorted(glob.glob(os.path.join(td, "p-*.png")), key=lambda p: int(re.findall(r"(\d+)\.png$", p)[0]))
        for n, f in enumerate(files, 1):
            im = Image.open(f).convert("RGB")
            if im.width > MAX_W:
                im = im.resize((MAX_W, round(im.height * MAX_W / im.width)), Image.LANCZOS)
            buf = io.BytesIO()
            im.save(buf, "WEBP", quality=QUALITY, method=6)
            open(os.path.join(cdir, f"p{n}.webp"), "wb").write(buf.getvalue())
            if n not in skip:
                out.append(buf.getvalue())
        return out


def section(pages, secret, title, extra=None):
    """Encrypt page images (and optional extra JSON, e.g. cards) under one key."""
    salt = secrets.token_bytes(16)
    key = derive(secret, salt)
    d = secrets.token_hex(8)
    os.makedirs(os.path.join(DATA, d))
    for i, page in enumerate(pages, 1):
        with open(os.path.join(DATA, d, f"{i}.bin"), "wb") as fh:
            fh.write(seal(key, page))
    out = {"title": title, "salt": b64(salt), "check": b64(seal(key, CHECK)), "dir": d, "pages": len(pages)}
    if extra is not None:
        with open(os.path.join(DATA, d, "cards.bin"), "wb") as fh:
            fh.write(seal(key, json.dumps(extra, ensure_ascii=False).encode()))
        out["cards"] = True
    return out


def card_payload(c, img_dir):
    """Inline item images (base64 JPEG) so the whole card set is one encrypted file."""
    c = json.loads(json.dumps(c))
    for it in c.get("items", []):
        if it.get("img"):
            path = os.path.join(img_dir, it["img"] + ".jpg")
            it["img"] = "data:image/jpeg;base64," + b64(open(path, "rb").read())
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", required=True)
    ap.add_argument("--codes", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--party-word")
    g.add_argument("--no-envelope-lock", action="store_true")
    ap.add_argument("--extra-env", help="folder of extra envelope pages, files named 'NN anything.pdf' (appended to that player's envelope)")
    ap.add_argument("--cards", help="plaintext cards JSON kept OUTSIDE the repo (abilities, secret, info, items)")
    ap.add_argument("--card-images", help="folder of item-card JPEGs named like the cards JSON 'img' fields")
    ap.add_argument("--envelopes-only", action="store_true",
                    help="re-render only the envelopes, keeping the existing send-ahead files")
    ap.add_argument("--host-guide", help="the Host & Co-host Guide PDF, shown behind --host-password")
    ap.add_argument("--host-password", help="password for the host guide (kept OUTSIDE the repo)")
    a = ap.parse_args()
    if bool(a.host_guide) != bool(a.host_password):
        sys.exit("--host-guide and --host-password go together")
    if a.host_password and len(norm(a.host_password)) < 10:
        sys.exit("Host password is too short: the guide contains the solution")

    cast = json.load(open(os.path.join(HERE, "cast.json"), encoding="utf-8"))
    codes = json.load(open(a.codes)) if os.path.exists(a.codes) else {}
    # Each player's password is their packet number ("01".."26"), the number on the
    # files Anthony sent them. The "is this you?" pop-up keeps people to their own packet.
    for c in cast:
        if c["num"] not in codes:
            sys.exit(f"No password for {c['num']} {c['player']} in {a.codes}")
    json.dump(codes, open(a.codes, "w"), indent=2)

    party = None if a.no_envelope_lock else norm(a.party_word)
    if party is not None and len(party) < 3:
        sys.exit("Party word is too short")

    old = {}
    if a.envelopes_only:
        old = {p["num"]: p for p in json.load(open(os.path.join(DATA, "index.json"), encoding="utf-8"))["players"]}
        for p in old.values():
            shutil.rmtree(os.path.join(DATA, p["env"]["dir"]), ignore_errors=True)
    else:
        if os.path.isdir(DATA):
            shutil.rmtree(DATA)
        os.makedirs(DATA)

    cards = json.load(open(a.cards, encoding="utf-8")) if a.cards else {}
    players = []
    for c in cast:
        code = norm(codes[c["num"]])
        env = render(find_pdf(os.path.join(a.packets, "2_Envelopes"), c["num"]),
                     ENV_SKIP_ALL | ENV_SKIP.get(c["num"], set()))
        if a.extra_env:
            for extra in sorted(glob.glob(os.path.join(a.extra_env, f"{c['num']} *.pdf"))):
                # a private murder lead goes on top ("read this first"); anything else at the end
                env = render(extra) + env if " lead" in os.path.basename(extra) else env + render(extra)
        env_secret = code + "|" + party if party else code + "|envelope"
        players.append({
            "num": c["num"], "player": c["player"], "character": c["character"],
            "aka": c["aka"], "tagline": c["tagline"], "side": c["side"],
            "sa": old[c["num"]]["sa"] if a.envelopes_only else
                  section(render(find_pdf(os.path.join(a.packets, "1_Send_ahead"), c["num"])), code, "Your packet"),
            "env": section(env, env_secret, "Your envelope",
                           card_payload(cards[c["num"]], a.card_images) if c["num"] in cards else None),
        })
        print(f"{c['num']} {c['player']:<18} send-ahead {players[-1]['sa']['pages']:>2} pp, envelope {len(env)} pp")

    index = {"version": 1, "iterations": ITER, "envelopeLocked": party is not None, "players": players}
    if a.host_guide:
        # Host & Co-host Guide: page images plus the PDF itself, under the host password.
        # Its own "HOST|" prefix keeps it apart from every player key.
        host_secret = "HOST|" + norm(a.host_password)
        host = section(render(a.host_guide), host_secret, "Host & Co-host Guide")
        salt = base64.b64decode(host["salt"])
        with open(os.path.join(DATA, host["dir"], "guide.bin"), "wb") as fh:
            fh.write(seal(derive(host_secret, salt), open(a.host_guide, "rb").read()))
        host["pdf"] = "guide.bin"
        index["host"] = host
        print(f"host guide {host['pages']} pp")
    elif a.envelopes_only:
        prev = json.load(open(os.path.join(DATA, "index.json"), encoding="utf-8"))
        if "host" in prev:
            index["host"] = prev["host"]
    json.dump(index, open(os.path.join(DATA, "index.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("Wrote", os.path.join(DATA, "index.json"))


if __name__ == "__main__":
    main()
