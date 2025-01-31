/*
 * ima-evm-utils - imafix2 mod by genBTC 2021 + 2022
 *
*/ 
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <getopt.h>
#include <keyutils.h>
#include <ctype.h>
#include <termios.h>
#include <assert.h>
#include <asm/byteorder.h>

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
//#include "hash_info.h"

#include "utils.h"

#define USE_FPRINTF

#include "imaevm.h"

struct command {
	char *name;
	int (*cmd_function)(struct command *cmd);
	int cmd;
	char *arg;
	char *msg;		/* extra info message */
};

static int g_argc;
static char **g_argv;
static int xattr = 1;
static int digest;
static int digsig;
static char *search_type;
static int recursive;
static dev_t fs_dev;

static char *cwd;
static char dirbuf[4096] = {0};

typedef int (*find_cb_t)(const char *path);
static int find(const char *path, int dts, find_cb_t cmd_function);

#define REG_MASK	(1 << DT_REG)
#define DIR_MASK	(1 << DT_DIR)
#define LNK_MASK	(1 << DT_LNK)
#define CHR_MASK	(1 << DT_CHR)
#define BLK_MASK	(1 << DT_BLK)

struct command cmds[];
static void print_usage(struct command *cmd);
static void usage(void);

static const char *xattr_ima = "security.ima";
static const char *PERSONAL_PRIVATE_KEY = "/etc/keys/signing_key.priv";
static const char *PERSONAL_PUBLIC_KEY = "/etc/keys/signing_key.x509";
static const char *PREFERRED_DEFAULT_HASH_ALGO = "sha512";

static int find_xattr(const char *list, int list_size, const char *xattr)
{
	int len;

	for (; list_size > 0; len++, list_size -= len, list += len) {
		len = strlen(list);
		if (!strcmp(list, xattr))
			return 1;
	}
	return 0;
}

static int sign_ima(const char *file, const char *key)
{
	unsigned char hash[MAX_DIGEST_SIZE];
	unsigned char sig[MAX_SIGNATURE_SIZE];
	int len, err;

	len = ima_calc_hash(file, hash);
	if (len <= 1)
		return len;
	assert(len <= sizeof(hash));

	len = sign_hash(imaevm_params.hash_algo, hash, len, key, NULL, sig + 1);
	if (len <= 1)
		return len;
	assert(len < sizeof(sig));

	/* add header */
	len++;
	sig[0] = EVM_IMA_XATTR_DIGSIG;

	if (xattr) {
		err = lsetxattr(file, xattr_ima, sig, len, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int hash_ima(const char *file)
{
	unsigned char hash[MAX_DIGEST_SIZE + 2]; /* +2 byte xattr header */
	int len, err, offset;
	int algo = imaevm_get_hash_algo(imaevm_params.hash_algo);

	if (algo < 0) {
		log_err("Unknown hash algo: %s\n", imaevm_params.hash_algo);
		return -1;
	}
	if (algo > PKEY_HASH_SHA1) {
		hash[0] = IMA_XATTR_DIGEST_NG;
		hash[1] = algo;
		offset = 2;
	} else {
		hash[0] = IMA_XATTR_DIGEST;
		offset = 1;
	}

	len = ima_calc_hash(file, hash + offset);
	if (len <= 1)
		return len;
	assert(len + offset <= sizeof(hash));

	len += offset;

	if (imaevm_params.verbose >= LOG_INFO)
		log_info("hash(%s): ", imaevm_params.hash_algo); //no \n

	if (xattr) {
		err = lsetxattr(file, xattr_ima, hash, len, 0);
		if (err < 0) {
			log_err("setxattr failed: %s\n", file);
			return err;
		}
	}

	return 0;
}

static int get_file_type(const char *path, const char *search_type)
{
	int err, dts = 0, i;
	struct stat st;

	for (i = 0; search_type[i]; i++) {
		switch (search_type[i]) {
		case 'f':
			dts |= REG_MASK; break;
		case 'd':
			dts |= DIR_MASK; break;
		case 's':
			dts |= BLK_MASK | CHR_MASK | LNK_MASK; break;
		case 'm':
			/* stay within the same filesystem*/
			err = lstat(path, &st);
			if (err < 0) {
				log_err("Failed to stat: %s\n", path);
				return err;
			}
			fs_dev = st.st_dev; /* filesystem to start from */
			break;
		}
	}

	return dts;
}

static int do_cmd(struct command *cmd, find_cb_t cmd_function)
{
	char *path = g_argv[optind++];
	int dts = REG_MASK; /* only regular files by default */

	if (!path) {
		usage();
		log_err("Parameters missing -\n");
		print_usage(cmd);
		return -1;
	}

	if (search_type) {
		dts = get_file_type(path, search_type);
		if (dts < 0)
			return dts;
	}

	if (recursive)
		return find(path, dts, cmd_function);
	else
		return cmd_function(path);
}

static int imafix2(const char *path);
static int cmd_imafix2(struct command *cmd_function)
{
	init_public_keys(PERSONAL_PUBLIC_KEY);
	imaevm_params.hash_algo = PREFERRED_DEFAULT_HASH_ALGO;

	return do_cmd(cmd_function, imafix2);
}

static int imafix2(const char *path)
{
	int size, len, err, digestlen = 0, ima = 0;
	char listbuf[1024];
	const char *key;
	uint8_t xattr_value[MAX_SIGNATURE_SIZE] = {0};
	uint8_t xdigest[MAX_DIGEST_SIZE] = {0};
	struct signature_v2_hdr *hdr;
//	uint32_t keyid;
	uint16_t sig_size = 0;

	/* re-measuring takes some time, but
	 * in some cases we can skip labeling if xattrs exists
	*/
	size = llistxattr(path, listbuf, sizeof(listbuf));
	if (size < 0) {
		log_errno("BUG: llistxattr() read list of xattrs failed!: %s\n", path);
		return -1;
	}
	ima = find_xattr(listbuf, size, xattr_ima);

	if (ima) {
//		if (imaevm_params.verbose > LOG_INFO)
//			log_info("IMA Found: %s\n", path);
		len = lgetxattr(path, xattr_ima, xattr_value, sizeof(xattr_value));
		if (len < 0) {
			log_errno("BUG: getxattr() on security.ima failed!: %s\n", path);
			return len;
		}
		//xattr_value[0]; 03 = evm_ima_xattr_type=EVM_IMA_XATTR_DIGSIG
		if (xattr_value[0] == EVM_IMA_XATTR_DIGSIG) {
			//(DIGSIG attribute, with 0206 = sigv2,SHA512)
			hdr = (struct signature_v2_hdr *)&xattr_value[1];
/*
			xattr_value[1]; hdr->
			 version hash_algo keyid sig_size sig
			   02       06   hexkeyid  hexlen
			02 = digsig_version=DIGSIG_VERSION_2
			06 = pkey_hash_algo=PKEY_HASH_SHA512
			hexkeyid = ab6f2050 (IMA keyid: last 8 chars of cert serial)
			hexlen = 0x0200=(512 in dec)
			//these last two we have to bswap for some reason:
			//keyid = __builtin_bswap32(hdr->keyid); */
			sig_size = __builtin_bswap16(hdr->sig_size);
		}
/* 		if (imaevm_params.verbose > LOG_INFO) {
			log_info("DIGSIG %d, HASH_ALGO %d, ", hdr->version, hdr->hash_algo);
			log_info("HEXKEYID %02x, hexlen %02x \n", keyid, sig_size);
			log_info("dump contents of security.ima: %d bytes\n", sig_size);
			log_dump(hdr->sig, sig_size);
		}
*/		// here means it must be a HASH. continue...:


		digestlen = ima_calc_hash(path, xdigest);
		if (digestlen <= 1) {
			log_err("BUG: ima_calc_hash() failed!: %d\n", digestlen);
			return digestlen;
		}
		//assert(digestlen <= sizeof(xdigest));
		if (imaevm_params.verbose > LOG_INFO) {
			log_info("ReCalc'dHash: ");
			log_dump(xdigest, digestlen);
		}
		//verify hash match
		//TODO: Files saved as other SHA algorithms need a different recalc
		if (xattr_value[0] == IMA_XATTR_DIGEST_NG &&
		    xattr_value[1] == PKEY_HASH_SHA512 ) {
			//(DIGEST_NG attribute always starts with 0406 for SHA512)
			if (digestlen == sizeof(xdigest) &&
				memcmp(&xattr_value[2], xdigest, digestlen) == 0) {
							//hash was OK
				if (imaevm_params.verbose > LOG_INFO)
					log_info("Verified OK! IMA-DIGEST-NG digest hash matches!\n");
				return 0;	//redundant, control flows to end of function next anyway
			}
			else {
				//bad hash. removexattr and redo it. (shortcut just write hash over it)
				if (imaevm_params.verbose >= LOG_INFO) {
					if (cwd)
						log_info("HASHFAIL: %s/%s \n", cwd,path);
					else
						log_info("HASHFAIL: %s \n", path);
				}
				if (imaevm_params.verbose > LOG_INFO)
					log_err("IMA-DIGEST-NG hash Verify Failed!\n");
				//return -1;
				//TODO: but continue on and fix the hash if its a dir. (for now, for my application)
				err = hash_ima(path);
				if (err && imaevm_params.verbose >= LOG_INFO)
					log_err("Verify-Hash failed, and then Commit-New-Hash failed also! error=%d\n", err);
				return err;
			}
		//if ima = -1. no digest (then its a signature, we can verify_sign on it)
		//verify signature match
		}
		else if (xattr_value[0] == EVM_IMA_XATTR_DIGSIG) {
			ima = ima_verify_signature(path, xattr_value, 9+sig_size, xdigest, digestlen);
			if (ima==0) {
				if (imaevm_params.verbose > LOG_INFO)
					log_info("Verified OK! IMA-DIGSIGv2 digest hash matches!\n");
				return 0;
			}
			else {
				if (imaevm_params.verbose >= LOG_INFO) {
					if (cwd)
						log_info("SIGNFAIL: %s/%s \n", cwd,path);
					else
						log_info("SIGNFAIL: %s \n", path);
				}
				if (imaevm_params.verbose > LOG_INFO)
					log_err("IMA-DIGSIGN hash Verify failed!");// error=%d\n", ima);
				return 1;
			}
		//if ima = -1. no signature (then we failed and the thing is corrupt)
		}
		else
			log_err("BUG: imafix2() - Something Else Bad Happened, wrong Hash Algo, or Data is unreadable. ABORT!\n");
		//return 0;.
		//TODO FIX THIS:
//>------------->
		//HASHFAIL: (null)//usr/share/doc
		//hash(sha512): /usr/src: verification failed: 0 (bad signature)
//<-------------<
		//hashfail comes from above. verification failfed comes from deep in libima
		//we do actually fix the file Commit-New-Hash so running it again produces other output:
		//HASHFAIL: (null)//usr/share/doc
		//hash(sha512): ^D|gentoo / #
	}
	else {
		log_info("IMA(fixhash): %s\n", path);
	//Manual mode:
		if (!digsig && !digest)
			digsig = 1;
		if (digsig) {
			key = imaevm_params.keyfile ? : PERSONAL_PRIVATE_KEY;
			err = sign_ima(path, key);
			if (err)
				return err;
		}
		else if (digest) {
			err = hash_ima(path);
			if (err)
				return err;
		}
	}
	return 0;
}

static int find(const char *path, int dts, find_cb_t cmd_function)
{
	struct dirent *de;
	DIR *dir;

	if (fs_dev) {
		struct stat st;
		int err = lstat(path, &st);

		if (err < 0) {
			log_err("Failed to stat: %s\n", path);
			return err;
		}
		if (st.st_dev != fs_dev)
			return 0;
	}

	dir = opendir(path);
	if (!dir) {
		log_err("Failed to open directory %s\n", path);
		return -1;
	}

	if (fchdir(dirfd(dir))) {
		log_err("Failed to chdir %s\n", path);
		return -1;
	}

	cwd = getcwd(dirbuf, sizeof(dirbuf));
	//log_debug("cwd: %s/ \n", cwd);

	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, "..") || !strcmp(de->d_name, "."))
			continue;
		log_debug("path: %s, type: %u\n", de->d_name, de->d_type);
		if (de->d_type == DT_DIR)
			find(de->d_name, dts, cmd_function);
		else if (dts & (1 << de->d_type))
			cmd_function(de->d_name);
	}

	if (chdir("..")) {
		log_err("Failed to chdir: %s\n", path);
		return -1;
	}

	cwd = getcwd(dirbuf, sizeof(dirbuf));
	//log_debug("cwd: %s/ \n", cwd);

	if (dts & DIR_MASK)
		cmd_function(path);

	closedir(dir);

	return 0;
}

static void print_usage(struct command *cmd)
{
	printf("usage: %s %s\n", cmd->name, cmd->arg ? cmd->arg : "");
}

static void print_all_usage(struct command *cmds)
{
	struct command *cmd;

	printf("commands:\n");

	for (cmd = cmds; cmd->name; cmd++) {
		if (cmd->arg)
			printf(" %s %s\n", cmd->name, cmd->arg);
		else if (cmd->msg)
			printf(" %s", cmd->msg);
	}
}

static int call_command(struct command *cmds, char *command)
{
	struct command *cmd;

	for (cmd = cmds; cmd->name; cmd++) {
		if (strcasecmp(cmd->name, command) == 0)
			return cmd->cmd_function(cmd);
	}
	printf("Invalid command: %s\n", command);
	return -1;
}

static void usage(void)
{
	printf("Usage: imafix2 [-v] [OPTIONS] <pathname>\n");
	print_all_usage(cmds);
	printf(
		"\n"
		"  -a, --hashalgo     sha512(default), sha1, sha224, sha256, sha384, md5, streebog, ripe-md, wp, tgr, etc\n"
		"  -s, --imasig       make IMA signature(default)\n"
		"  -d, --imahash      make IMA hash\n"
		"  -k, --key          path to signing key (defaults: /etc/keys/signing_key.x509 & /etc/keys/signing_key.priv )\n"
		"  -r, --recursive    recurse sub-directories\n"
		"  -t, --type         filter search by type: -t 'fdsm'\n"
		"                     f: Files(default), d: Directory, s: block/char/Symlink\n"
		"                     m: stay on the same filesystem (like 'find -xdev')\n"
		"  -v                 verbose, increase verbosity level++\n"
		"  -h, --help         display this help and exit\n"
		"  --version          print version number and exit\n"
		"\n");
}

struct command cmds[] = {
	{"imafix2", cmd_imafix2, 0, "[-t fdsxm] path", "Recursively check/fix filesystem xattrs security.ima hashes \n"},
	{"--version", NULL, 0, ""},
	{0, 0, 0, NULL}
};

static struct option opts[] = {
	{"help", 0, 0, 'h'},
	{"imasig", 0, 0, 's'},
	{"imahash", 0, 0, 'd'},
	{"hashalgo", 1, 0, 'a'},
	{"key", 1, 0, 'k'},
	{"type", 1, 0, 't'},
	{"recursive", 0, 0, 'r'},
	{"version", 0, 0, 129},
	{}

};

//  MAIN
int main(int argc, char *argv[])
{
	int err = 0, c, lind;
	g_argv = argv;
	g_argc = argc;

	while (1) {
		c = getopt_long(argc, argv, "hvdsa:k:t:r", opts, &lind);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			exit(0);
			break;
		case 'v':
			imaevm_params.verbose++;
			break;
		case 'd':
			digest = 1;
			break;
		case 's':
			digsig = 1;
			break;
		case 'a':
			imaevm_params.hash_algo = optarg;
			break;
		case 'k':
			imaevm_params.keyfile = optarg;
			break;
		case 't':
			search_type = optarg;
			break;
		case 'r':
			recursive = 1;
			break;
		case 129:
			printf("imafix2 version %s\n", VERSION);
			exit(0);
			break;
		default:
			log_err("getopt() returned: %d (%c)\n", c, c);
		}
	}

    err = call_command(cmds, "imafix2");

	if (err) {
		unsigned long error;

		if (errno)
			log_err("errno: %s (%d)\n", strerror(errno), errno);
		for (;;) {
			error = ERR_get_error();
			if (!error)
				break;
			log_err("%s\n", ERR_error_string(error, NULL));
		}
		if (err < 0)
			err = 125;
	}
	//OpenSSL cleanup
	ERR_free_strings();
	EVP_cleanup();
	BIO_free(NULL);
	return err;
}
