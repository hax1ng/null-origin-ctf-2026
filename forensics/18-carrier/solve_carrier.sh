#!/usr/bin/env bash
# Recover the Carrier flag from deleted single-byte files on an ext4 image.
#
# The flag was split one character per file, then every file was deleted. The
# names (directory entries) are gone, but ext4 never reused the inodes' extents,
# so Sleuth Kit can still read each byte back by inode number.
#
# Two groups of deleted 1-byte files exist. Only inodes 2299-2339 were *created*
# inside the incident window (see incident-notes.txt); 2263-2298 are old debris.
# istat shows creation vs. deletion times to tell them apart.
set -euo pipefail

IMG="${1:-carrier.img}"

# Reassemble the flag: icat each in-window inode in ascending order.
for inode in $(seq 2299 2339); do
    icat "$IMG" "$inode"
done
echo

# Expected: Null0rigin{the_extents_outlived_the_name}
