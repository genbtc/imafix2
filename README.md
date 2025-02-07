# imafix2, v1.0
ima-evm-utils - imafix2 mod by genBTC 2021 + 2022 + 2025
# IMA Signs files, compatible with ima-evm-utils.
Operate on single files or directory, option to recurse subdirectories,

Gathers the list of files to be signed, hashes them with SHA512,

Then private key is used to create a signed signature of the file digest.

Saved to the linux filesystem xattrs, as security.ima, ready for IMA Appraisal!

## Usage:
--help
```
genr8eofl@genr8too ~/src/imafix2 $ ./src/imafix2 --help
Usage: imafix2 [-v] [OPTIONS] <pathname>
commands:
 imafix2 [-t fdsxm] path
 --version 

  -k, --key          path to signing key (defaults: /etc/keys/signing_key.x509 & /etc/keys/signing_key.priv )
  -a, --hashalgo     sha512(default), sha1, sha224, sha256, sha384, md5, streebog, ripe-md, wp, tgr, etc
  -s, --imasig       make IMA signature(default)
  -d, --imahash      make IMA hash
  -f, --force        force IMA sign (after SIGNFAILs)
  -r, --recursive    recurse sub-directories
  -t, --type         filter search by type: -t 'fdsm'
                     f: Files(default), d: Directory, s: block/char/Symlink
                     m: stay on the same filesystem (like 'find -xdev')
  -v                 verbose, increase verbosity level++
  -h, --help         display this help and exit
  --version          print version number and exit

```

### written in C, forked from ima-evm-utils, and heavily modified.
