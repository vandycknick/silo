# Producer-original raw xattr evidence

Source names/values were set on real Linux inodes and independently collected before/after archiving. The retained original complete attribute set, raw length-framed PAX records, archive hashes and actual extraction listings are authoritative evidence. No producer dialect is guessed from incidental tar headers. In particular, agreement between Silo and an extractor does not prove agreement with the original inode.

| Producer | Stage | Outcome | Original-to-extracted differences | Error |
|---|---|---|---:|---|
| gnu-tar-file-00 | extract | policy-difference | 3 |   |
| gnu-tar-file-01 | extract | policy-difference | 3 |   |
| gnu-tar-file-02 | extract | policy-difference | 3 |   |
| gnu-tar-file-03 | extract | policy-difference | 3 |   |
| gnu-tar-file-04 | extract | policy-difference | 3 |   |
| gnu-tar-file-05 | extract | policy-difference | 3 |   |
| gnu-tar-file-06 | extract | policy-difference | 3 |   |
| gnu-tar-file-07 | extract | policy-difference | 3 |   |
| gnu-tar-file-08 | extract | policy-difference | 3 |   |
| gnu-tar-complete-set | extract | policy-difference | 3 |   |
| libarchive-file-00 | extract | semantic-difference | 4 |   |
| libarchive-file-01 | extract | semantic-difference | 4 |   |
| libarchive-file-02 | extract | semantic-difference | 4 |   |
| libarchive-file-03 | extract | semantic-difference | 4 |   |
| libarchive-file-04 | extract | semantic-difference | 4 |   |
| libarchive-file-05 | extract | semantic-difference | 4 |   |
| libarchive-file-06 | extract | semantic-difference | 4 |   |
| libarchive-file-07 | extract | policy-difference | 3 |   |
| libarchive-file-08 | extract | policy-difference | 3 |   |
| libarchive-complete-set | extract | semantic-difference | 11 |   |
| star-file-00 | extract | semantic-difference | 4 |   |
| star-file-01 | extract | policy-difference | 3 |   |
| star-file-02 | extract | policy-difference | 3 |   |
| star-file-03 | extract | policy-difference | 3 |   |
| star-file-04 | extract | policy-difference | 3 |   |
| star-file-05 | extract | policy-difference | 3 |   |
| star-file-06 | extract | policy-difference | 3 |   |
| star-file-07 | extract | policy-difference | 3 |   |
| star-file-08 | extract | policy-difference | 3 |   |
| star-complete-set | extract | semantic-difference | 5 |   |

Run the separate qualify-changesets --acquired command on this directory. Its JSON+Markdown retains producer-original->Silo, producer-original->containerd and Silo->containerd differences separately, including typed Silo ambiguity rejection. A matching round trip cannot identify the intent of wire-identical raw/escaped SCHILY records.
