# Carrier

**Category:** Forensics | **Difficulty:** Hard | **Points:** 600 | **Flag:** `Null0rigin{the_extents_outlived_the_name}`

## Challenge Description

> A carrier is not the message. It is what the message rode in on. It is the
> part everyone throws away.

We get four files:

```text
carrier.img          # 96 MiB ext4 filesystem image
carrier.sealed       # confirmation material
incident-notes.txt   # the incident window (included here)
verify               # local checker
```

> Note: part of the internal forensics chain — chain-internal flag format is
> `Null0rigin{...}` (with a zero). The 96 MiB `carrier.img` is omitted from this
> public repo (large binary artifact); the solve below reproduces against it.

The short version: the flag was split one character per file, then every file
was deleted. The *names* vanished, but ext4 still knew where each one-byte
payload lived.

## Initial Analysis

```bash
file carrier.img carrier.sealed verify
# carrier.img: Linux rev 1.0 ext4 filesystem data
```

So it's a real ext4 filesystem — investigate it directly, no need to mount and
risk changing it. The incident notes are load-bearing:

```text
Confirmed incident window (UTC):
2026-09-15T13:34:02+00:00 to 2026-09-15T13:34:03+00:00
Everything created outside that window is unrelated background activity.
```

Note the word **created** — not deleted, not modified. That distinction is the
whole challenge.

```bash
dumpe2fs -h carrier.img 2>/dev/null          # 4096-byte blocks
debugfs -R 'ls -l -p /' carrier.img          # 2000+ random *.dat decoys
debugfs -R lsdel carrier.img                 # 77 deleted inodes, 2263..2339
```

`lsdel` reports 77 deleted inodes (2263–2339), every one exactly **one byte**.

## The Vulnerability / Core Concept

An **inode** stores a file's size, timestamps, and where its data blocks live;
the **filename** lives separately in a directory entry. Deleting a file removes
the directory entry and marks the inode/blocks reusable — but it does **not**
immediately wipe the bytes. Until something overwrites those blocks, the data is
recoverable.

There are *two* groups of deleted one-byte files, and deletion time can't
separate them — both were deleted during the incident. Creation time can. Using
Sleuth Kit's `istat` to read the full timestamps:

```bash
for inode in $(seq 2263 2339); do
    echo "== inode $inode =="
    istat carrier.img "$inode" | sed -n '/Inode Times:/,/Direct Blocks:/p'
done
```

- Inodes **2263–2298**: created `09:34:00 EDT` — old background debris.
- Inodes **2299–2339**: created `09:34:02 EDT`, deleted `09:34:03 EDT`.

Tools show local EDT (UTC-4 on that date), so `09:34:02 EDT = 13:34:02 UTC` —
exactly the incident window. Inodes 2299–2339 are the real artifacts; the first
group is the trap for anyone who recovers *every* deleted byte.

## Exploitation

`icat` extracts a file by inode. Read the in-window inodes in ascending order
and concatenate their single bytes (`solve_carrier.sh`):

```bash
for inode in $(seq 2299 2339); do
    icat carrier.img "$inode"
done
echo
# Null0rigin{the_extents_outlived_the_name}
```

The recovered bytes start `4e 75 6c 6c` = `Null` and continue one character at a
time to the closing brace. Verify:

```bash
./verify 'Null0rigin{the_extents_outlived_the_name}'
# CORRECT. carrier solved.
```

## Flag

`Null0rigin{the_extents_outlived_the_name}`

## Key Takeaways

- In ext-family filesystems the filename (directory entry) and the data
  (inode + extents) are separate. Deleting drops the name but often leaves the
  extents and blocks intact — Sleuth Kit `lsdel` + `icat` reads them back.
- Read the incident notes literally: "created" ≠ "deleted" ≠ "modified".
  Timestamp discipline (`istat`, and watch the EDT→UTC offset) is what filters
  the real artifacts from identical-looking debris.
- A flag can be smeared across many tiny files; the carrier (the files) is
  disposable, the payload (the bytes/extents) survives.
