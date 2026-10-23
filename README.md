# A Dead Man's Chest: crew papers

A small static site where each player at our *A Dead Man's Chest* murder mystery
(a Freeform Games freeform, hosted at Anthony's on the night of the party) can look up their own character packet.

1. A player types their name or their character's name.
2. A pop-up checks they picked themselves (each packet is for one player only).
3. They enter their **password**: the number on the packet file Anthony sent them.
4. They see their **send-ahead packet** ("Before the party").
5. Their **envelope** stays sealed until Anthony announces the **party word** at the game.
6. The **Cards** tab (also unlocked by the party word) lists their abilities, Secret, Information and starting items. Each card has a full-screen **Show** button; abilities have **Use** buttons that tick off uses, with **Undo** and a timestamped activity log saved on that phone.

## Privacy

Every page is stored only in encrypted form in `data/`, using AES-256-GCM.

- The key for a player's send-ahead packet comes from their password, run through PBKDF2-SHA256 with 400k iterations and a per-section salt.
- The key for their envelope comes from their password plus the party word.

Without the password, the files in this repo are noise. That holds even though the repo is public. Inside the party it's an honor system: passwords are deliberately simple, and the pop-up asks people to open only their own packet. The site never sends codes anywhere; all decryption happens in the browser.

The cast list in `data/index.json` (player, character, side, one-line description) is public, the same as the casting list players already received.

**The passwords and the party word are NOT in this repo.** Anthony has them.

## Rebuilding

To rebuild after a packet changes, keep `codes.json` (the passwords) *outside* the repo:

```bash
pip install pillow cryptography      # plus poppler-utils for pdftoppm
python3 tools/build_site.py \
  --packets "/path/to/A_Dead_Mans_Chest/Packets" \
  --codes ../codes.json \
  --party-word "THE-PARTY-WORD" \   # or --no-envelope-lock to open envelopes now
  --cards ../cards_data.json --card-images ../crops_jpg   # card text + item images, kept OUTSIDE the repo
git add -A && git commit -m "Rebuild packets" && git push
```

`--packets` must hold `1_Send_ahead/` and `2_Envelopes/`, with files named `NN Player - Character….pdf`.

## Hosting

GitHub Pages serves the site: Settings → Pages → Deploy from branch → `main` / root.
The site has no build step and no dependencies.

---
*A Dead Man's Chest* © Freeform Games LLP. Shared privately with the players of one party; not for redistribution.
