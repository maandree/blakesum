/* See LICENSE file for copyright and license details. */
#include "common.h"

const char *argv0 = "bsum";

static int lenght_by_command_name = 0;

static int flag_check = 0;
static int flag_binary = 0;
static int flag_lower = 0;
static int flag_upper = 0;
static int flag_hex = 0;
static int flag_zero = 0;
static int length;

static void
usage(void)
{
	fprintf(stderr, "usage: %s%s [-c | -B | -L | -U] [-xz] [file] ...",
	        argv0, lenght_by_command_name ? "" : " [-l bits]");
	exit(2);
}

static void
get_lenght_by_command_name(const char *command)
{
	const char *p;
	p = strrchr(command, '/');
	p = p ? &p[1] : command;
	if (strstr(p, "b224sum"))
		lenght_by_command_name = 224;
	else if (strstr(p, "b256sum"))
		lenght_by_command_name = 256;
	else if (strstr(p, "b384sum"))
		lenght_by_command_name = 384;
	else if (strstr(p, "b512sum"))
		lenght_by_command_name = 512;
}

static int
hash_fd_blake(int fd, const char *fname, int decode_hex, unsigned char hash[], void *state,
              void (*init_func)(void *state), size_t (*update_func)(void *state, const void *msg, size_t n),
              size_t (*get_buf_size_func)(size_t bytes, size_t bits, const char *suffix),
              void (*digest_func)(void *state, void *msg, size_t bytes, size_t bits, const char *suffix, unsigned char out[]))
{
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0;
	size_t off = 0;
	size_t req;
	ssize_t r;
	int ok;
	init_func(state);
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
			off += update_func(state, &buf[off], len - off);
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
	req = get_buf_size_func(len, 0, NULL);
	if (req > size)
		buf = erealloc(buf, size);
	libblake_blake224_digest(state, buf, len, 0, NULL, hash);
	free(buf);
	return 0;
}

static int
hash_fd_blake224(int fd, const char *fname, int decode_hex, unsigned char hash[])
{
	struct libblake_blake224_state state;
	return hash_fd_blake(fd, fname, decode_hex, hash, &state,
	                     (void (*)(void *))&libblake_blake224_init,
	                     (size_t (*)(void *, const void *, size_t))&libblake_blake224_update,
	                     &libblake_blake224_digest_get_required_input_size,
	                     (void (*)(void *, void *, size_t, size_t, const char *, unsigned char[]))&libblake_blake224_digest);
}

static int
hash_fd_blake256(int fd, const char *fname, int decode_hex, unsigned char hash[])
{
	struct libblake_blake256_state state;
	return hash_fd_blake(fd, fname, decode_hex, hash, &state,
	                     (void (*)(void *))&libblake_blake256_init,
	                     (size_t (*)(void *, const void *, size_t))&libblake_blake256_update,
	                     &libblake_blake256_digest_get_required_input_size,
	                     (void (*)(void *, void *, size_t, size_t, const char *, unsigned char[]))&libblake_blake256_digest);
}

static int
hash_fd_blake384(int fd, const char *fname, int decode_hex, unsigned char hash[])
{
	struct libblake_blake384_state state;
	return hash_fd_blake(fd, fname, decode_hex, hash, &state,
	                     (void (*)(void *))&libblake_blake384_init,
	                     (size_t (*)(void *, const void *, size_t))&libblake_blake384_update,
	                     &libblake_blake384_digest_get_required_input_size,
	                     (void (*)(void *, void *, size_t, size_t, const char *, unsigned char[]))&libblake_blake384_digest);
}

static int
hash_fd_blake512(int fd, const char *fname, int decode_hex, unsigned char hash[])
{
	struct libblake_blake512_state state;
	return hash_fd_blake(fd, fname, decode_hex, hash, &state,
	                     (void (*)(void *))&libblake_blake512_init,
	                     (size_t (*)(void *, const void *, size_t))&libblake_blake512_update,
	                     &libblake_blake512_digest_get_required_input_size,
	                     (void (*)(void *, void *, size_t, size_t, const char *, unsigned char[]))&libblake_blake512_digest);
}

int
hash_fd(int fd, const char *fname, int decode_hex, unsigned char hash[])
{
	int ret;

	if (length == 224)
		ret = hash_fd_blake224(fd, fname, decode_hex, hash);
	else if (length == 256)
		ret = hash_fd_blake256(fd, fname, decode_hex, hash);
	else if (length == 384)
		ret = hash_fd_blake384(fd, fname, decode_hex, hash);
	else if (length == 512)
		ret = hash_fd_blake512(fd, fname, decode_hex, hash);
	else
		abort();

	return ret;
}

int
main(int argc, char *argv[])
{
	int status = 0;
	int output_case;
	char newline;

	if (argv[0])
		get_lenght_by_command_name(argv[0]);

	length = lenght_by_command_name;

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
		if (length != 224 && length != 256 && length != 384 && length != 512) {
			fprintf(stderr, "%s: valid arguments for -l are 224 (default), 256, 384, and 512\n", argv0);
			return 2;
		}
		break;
	default:
		usage();
	} ARGEND;

	if (flag_check + flag_binary + flag_lower + flag_upper > 1)
		usage();

	if (!length)
		length = 224;

	newline = flag_zero ? '\0' : '\n';
	if (flag_check) {
		if (!argc) {
			status |= -check_and_print("-", (size_t)length, flag_hex, newline);
		} else {
			for (; *argv; argv++)
				status |= -check_and_print(*argv, (size_t)length, flag_hex, newline);
		}
	} else {
		output_case = flag_binary ? -1 : flag_upper;
		if (!argc) {
			status |= -hash_and_print("-", (size_t)length, flag_hex, newline, output_case);
		} else {
			for (; *argv; argv++)
				status |= -hash_and_print(*argv, (size_t)length, flag_hex, newline, output_case);
		}
	}

	if (fflush(stdout) || ferror(stdout) || fclose(stdout)) {
		fprintf(stderr, "%s: %s\n", argv0, strerror(errno));
		return 2;
	}
	return status;
}
