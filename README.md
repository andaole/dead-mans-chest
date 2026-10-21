# A Dead Man's Chest: crew papers

A small static site where each player at our *A Dead Man's Chest* murder mystery
(a Freeform Games freeform, hosted at Anthony's on the night of the party) can look up their own character packet.

1. A player types their name or their character's name.
2. They enter their **code**: their group plus two digits Anthony texted them (e.g. `FURY-27`).
3. They see their **send-ahead packet** ("Before the party").
4. Their **envelope** stays sealed until Anthony announces the **party word** at the game.

## Privacy

Every page is stored only in encrypted form in `data/`, using AES-256-GCM.

- The key for a player's send-ahead packet comes from their code, run through PBKDF2-SHA256 with 400k iterations and a per-section salt.
- The key for their envelope comes from their code plus the party word.

Without the right code, the files in this repo are noise. That holds even though the repo is public. Codes are deliberately easy to remember (group + two digits). That keeps out casual peeking, not a determined snoop, which is fine for a party. The site never sends codes anywhere; all decryption happens in the browser.

The cast list in `data/index.json` (player, character, side, one-line description) is public, the same as the casting list players already received.

**The codes and the party word are NOT in this repo.** Anthony has them.

## Rebuilding

To rebuild after a packet changes, keep `codes.json` *outside* the repo so everyone's codes stay the same:

```bash
pip install pillow cryptography      # plus poppler-utils for pdftoppm
python3 tools/build_site.py \
  --packets "/path/to/A_Dead_Mans_Chest/Packets" \
  --codes ../codes.json \
  --party-word "THE-PARTY-WORD"      # or --no-envelope-lock to open envelopes now
git add -A && git commit -m "Rebuild packets" && git push
```

`--packets` must hold `1_Send_ahead/` and `2_Envelopes/`, with files named `NN Player - Character….pdf`.

## Hosting

GitHub Pages serves the site: Settings → Pages → Deploy from branch → `main` / root.
The site has no build step and no dependencies.

---
*A Dead Man's Chest* © Freeform Games LLP. Shared privately with the players of one party; not for redistribution.
