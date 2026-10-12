#!/usr/bin/env python3
# Given target = V1*[0:32] = SHA256(prefix1_0 + flag), recover flag.
# flag = "Null0rigin{" + body + "}", total 34 bytes -> body = 22 chars.
import hashlib, sys, itertools

PREFIX1_0 = b'NULL0RIGIN/REV/CASCADE/v1|inner|24-palimpsest|1|' + (0).to_bytes(8,'little') + b'|'
VOCAB = "bleed erase faint folio gall ink leaf marginal overwrite quire rebind recur reuse scrape seam shift underwriting vellum wash".split()
BODYLEN = 22

def check(flag_body, target):
    flag = b'Null0rigin{' + flag_body.encode() + b'}'
    return hashlib.sha256(PREFIX1_0 + flag).digest() == target

def gen_word_bodies(total, with_number):
    # yield bodies of exactly `total` chars: words joined by '_', optional trailing _DDDD
    # DFS over words; if with_number, reserve trailing "_DDDD" (5 chars) filled later.
    results = []
    def dfs(parts, length):
        if with_number:
            # need words part length == total-5, then append _DDDD
            if length == total-5 and parts:
                results.append(('_'.join(parts), True))
                return
            if length >= total-5:
                return
        else:
            if length == total and parts:
                results.append(('_'.join(parts), False))
                return
            if length >= total:
                return
        for w in VOCAB:
            add = len(w) + (1 if parts else 0)
            dfs(parts+[w], length+add)
    dfs([], 0)
    return results

def main():
    target = bytes.fromhex(sys.argv[1].strip())
    n=0
    for with_number in (True, False):
        bodies = gen_word_bodies(BODYLEN, with_number)
        for body, has_num in bodies:
            if has_num:
                for d in range(10000):
                    fb = f"{body}_{d:04d}"
                    n+=1
                    if check(fb, target):
                        print("FLAG: Null0rigin{%s}"%fb); return
            else:
                n+=1
                if check(body, target):
                    print("FLAG: Null0rigin{%s}"%body); return
    print("no match after", n, "candidates")

if __name__=="__main__":
    main()
