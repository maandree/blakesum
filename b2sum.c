/* See LICENSE file for copyright and license details. */
#include "common.h"

const char *argv0 = "b2sum";

static int flag_check = 0;
static int flag_binary = 0;
static int flag_lower = 0;
static int flag_upper = 0;
static int flag_small = 0;
static int flag_extended = 0;
static int flag_hex = 0;
static int flag_zero = 0;
static int length = 0;
static long long int xlength = 0;

static size_t hashlen;

static void
usage(void)
{
	/* TODO add support for key, salt, and personalization */
	/* TODO add support for parallel versions */
	/* TODO add support for tree hashing */
	fprintf(stderr, "usage: %s [-l bits | -X bits] [-c | -B | -L | -U] [-sxz] [file] ...", argv0);
	exit(2);
}

static int
hash_fd_blake2bs(int fd, const char *fname, int decode_hex, unsigned char hash[])
{
	struct libblake_blake2b_state state2b;
	struct libblake_blake2b_params params2b;
	struct libblake_blake2s_state state2s;
	struct libblake_blake2s_params params2s;
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0;
	size_t off = 0;
	size_t req;
	ssize_t r;
	int ok;
	if (flag_small) {
		memset(&params2s, 0, sizeof(params2s));
		params2s.digest_len = (uint_least8_t)length;
		params2s.fanout = 1;
		params2s.depth = 1;
		libblake_blake2s_init(&state2s, &params2s, NULL);
	} else {
		memset(&params2b, 0, sizeof(params2b));
		params2b.digest_len = (uint_least8_t)length;
		params2b.fanout = 1;
		params2b.depth = 1;
		libblake_blake2b_init(&state2b, &params2b, NULL);
	}
	for (;;) {
		if (len == size)
			buf = erealloc(buf, size += 8 << 10);
		r = read(fd, &buf[len], size - len);
		if (r <= 0) {
			if (!r)
				break;
			if (errno == EINTR)
				continue;
			fprintf(stderr, "%s: %s: %s\n", argv0, fname, strerror(errno));
			free(buf);
			return -1;
		}
		len += (size_t)r;
		if (!decode_hex) {
			if (flag_small)
				off += libblake_blake2s_update(&state2s, &buf[off], len - off);
			else
				off += libblake_blake2b_update(&state2b, &buf[off], len - off);
			if (off == len)
				off = 0;
		}
	}
	if (off)
		memmove(&buf[0], &buf[off], len -= off);
	if (decode_hex) {
		len = libblake_decode_hex(buf, len, buf, &ok);
		if (!ok) {
			fprintf(stderr, "%s: %s: %s\n", argv0, fname, "invalid hexadecimal input");
			free(buf);
			return -1;
		}
	}
	if (flag_small)
		req = libblake_blake2s_digest_get_required_input_size(len);
	else
		req = libblake_blake2b_digest_get_required_input_size(len);
	if (req > size)
		buf = erealloc(buf, size);
	if (flag_small)
		libblake_blake2s_digest(&state2s, buf, len, 0, hashlen / 8, hash);
	else
		libblake_blake2b_digest(&state2b, buf, len, 0, hashlen / 8, hash);
	free(buf);
	return 0;
}

static int
hash_fd_blake2xbs(int fd, const char *fname, int decode_hex, unsigned char hash[])
{
	struct libblake_blake2xb_state state2xb;
	struct libblake_blake2xb_params params2xb;
	struct libblake_blake2xs_state state2xs;
	struct libblake_blake2xs_params params2xs;
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0;
	size_t off = 0;
	size_t req;
	size_t i, n;
	ssize_t r;
	int ok;
	if (flag_small) {
		memset(&params2xs, 0, sizeof(params2xs));
		params2xs.digest_len = (uint_least8_t)length;
		params2xs.fanout = 1;
		params2xs.depth = 1;
		params2xs.xof_len = (uint_least16_t)xlength;
		libblake_blake2xs_init(&state2xs, &params2xs, NULL);
	} else {
		memset(&params2xb, 0, sizeof(params2xb));
		params2xb.digest_len = (uint_least8_t)length;
		params2xb.fanout = 1;
		params2xb.depth = 1;
		params2xb.xof_len = (uint_least32_t)xlength;
		libblake_blake2xb_init(&state2xb, &params2xb, NULL);
	}
	for (;;) {
		if (len == size)
			buf = erealloc(buf, size += 8 << 10);
		r = read(fd, &buf[len], size - len);
		if (r <= 0) {
			if (!r)
				break;
			if (errno == EINTR)
				continue;
			fprintf(stderr, "%s: %s: %s\n", argv0, fname, strerror(errno));
			free(buf);
			return -1;
		}
		len += (size_t)r;
		if (!decode_hex) {
			if (flag_small)
				off += libblake_blake2xs_update(&state2xs, &buf[off], len - off);
			else
				off += libblake_blake2xb_update(&state2xb, &buf[off], len - off);
			if (off == len)
				off = 0;
		}
	}
	if (off)
		memmove(&buf[0], &buf[off], len -= off);
	if (decode_hex) {
		len = libblake_decode_hex(buf, len, buf, &ok);
		if (!ok) {
			fprintf(stderr, "%s: %s: %s\n", argv0, fname, "invalid hexadecimal input");
			free(buf);
			return -1;
		}
	}
	if (flag_small)
		req = libblake_blake2xs_predigest_get_required_input_size(&state2xs);
	else
		req = libblake_blake2xb_predigest_get_required_input_size(&state2xb);
	if (req > size)
		buf = erealloc(buf, size);
	if (flag_small)
		libblake_blake2xs_predigest(&state2xs, buf, len, 0);
	else
		libblake_blake2xb_predigest(&state2xb, buf, len, 0);
	if (flag_small) {
		for (i = 0; i * 32 < hashlen / 8; i++) { /* TODO this could be done parallel (but align hash) (also below) */
			n = (i + 1) * 32 > hashlen / 8 ? hashlen / 8 - i * 32 : 32;
			libblake_blake2xs_digest(&state2xs, (uint_least32_t)i, (uint_least8_t)n, &hash[i * 32]);
		}
	} else {
		for (i = 0; i * 64 < hashlen / 8; i++) {
			n = (i + 1) * 64 > hashlen / 8 ? hashlen / 8 - i * 64 : 64;
			libblake_blake2xb_digest(&state2xb, (uint_least32_t)i, (uint_least8_t)n, &hash[i * 64]);
		}
	}
	free(buf);
	return 0;
}

int
hash_fd(int fd, const char *fname, int decode_hex, unsigned char hash[])
{
	int ret;

	if (flag_extended)
		ret = hash_fd_blake2xbs(fd, fname, decode_hex, hash);
	else
		ret = hash_fd_blake2bs(fd, fname, decode_hex, hash);

	return ret;
}

int
main(int argc, char *argv[])
{
	int status = 0;
	int output_case;
	char newline;

	ARGBEGIN {
	case 'c':
		flag_check = 1;
		break;
	case 'B':
		flag_binary = 1;
		break;
	case 'L':
		flag_lower = 1;
		flag_upper = 0;
		break;
	case 'U':
		flag_upper = 1;
		flag_lower = 0;
		break;
	case 's':
		flag_small = 1;
		break;
	case 'x':
		flag_hex = 1;
		break;
	case 'z':
		flag_zero = 1;
		break;
	case 'l':
		if (length)
			usage();
		length = atoi(ARG());
		if (length & 7 || !length || length > 512) {
			fprintf(stderr, "%s: valid arguments for -l\n", argv0);
			return 2;
		}
		break;
	case 'X':
		if (flag_extended)
			usage();
		flag_extended = 1;
		xlength = atoll(ARG());
		if (xlength & 7 || !xlength || xlength > 34359738360LL) {
			fprintf(stderr, "%s: valid arguments for -X\n", argv0);
			return 2;
		}
		break;
	default:
		usage();
	} ARGEND;

	if (flag_check + flag_binary + flag_lower + flag_upper > 1 ||
	    (length && flag_extended))
		usage();

	if (!length)
		length = flag_small ? 256 : 512;
	else if (flag_small && length > 256)
		fprintf(stderr, "%s: valid arguments for -l\n", argv0);
	else if (flag_small && xlength > 524280LL)
		fprintf(stderr, "%s: valid arguments for -X\n", argv0);

	hashlen = flag_extended ? (size_t)xlength : (size_t)length;
	length /= 8;
	xlength /= 8;

	newline = flag_zero ? '\0' : '\n';
	if (flag_check) {
		if (!argc) {
			status |= -check_and_print("-", hashlen, flag_hex, newline);
		} else {
			for (; *argv; argv++)
				status |= -check_and_print(*argv, hashlen, flag_hex, newline);
		}
	} else {
		output_case = flag_binary ? -1 : flag_upper;
		if (!argc) {
			status |= -hash_and_print("-", hashlen, flag_hex, newline, output_case);
		} else {
			for (; *argv; argv++)
				status |= -hash_and_print(*argv, hashlen, flag_hex, newline, output_case);
		}
	}

	if (fflush(stdout) || ferror(stdout) || fclose(stdout)) {
		fprintf(stderr, "%s: %s\n", argv0, strerror(errno));
		return 2;
	}
	return status;
}
