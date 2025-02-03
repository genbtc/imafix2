# imafix2, v1.0
ima-evm-utils - imafix2 mod by genBTC 2021 + 2022 + 2025
# IMA Signs files, compatible with ima-evm-utils.
Open a directory, scan for a list of files, hash them with SHA512, write a private key signed signature
to the linux filesystem xattrs, as security.ima - or as fallback - user.ima.
Also supports taking list of files by -f files.txt, or piped to stdin.
