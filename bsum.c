/* See LICENSE file for copyright and license details. */
#include "common.h"

const char *argv0 = "bsum";

static int lenght_by_command_name = 0;

static void
usage(void)
{
	fprintf(stderr, "usage: %s%s [-c | -B | -L | -U] [-xz] [file] ...",
	        argv0, lenght_by_command_name ? "" : " [-l bits]");
	exit(2);
}

static void *
erealloc(void *ptr, size_t n)
{
	ptr = realloc(ptr, n);
	if (!ptr) {
		fprintf(stderr, "%s: %s\n", argv0, strerror(errno));
		exit(2);
	}
	return ptr;
}

static void
get_lenght_by_command_name(const char *command)
{
	const char *p;
	p = strrchr(command, '/');
	p = p ? &p[1] : command;
	if (strstr(p, "b224sum")) {
		lenght_by_command_name = 224;
	} else if (strstr(p, "b256sum")) {
		lenght_by_command_name = 256;
	} else if (strstr(p, "b384sum")) {
		lenght_by_command_name = 384;
	} else if (strstr(p, "b512sum")) {
		lenght_by_command_name = 512;
	}
}

static int
hash_file_blake224(int fd, const char *fname, int decode_hex, unsigned char hash[], size_t *hash_lenp)
{
	struct libblake_blake224_state state;
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0;
	size_t off = 0;
	size_t req;
	ssize_t r;
	int ok;
	libblake_blake224_init(&state);
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
			return -1;
		}
		len += (size_t)r;
		if (!decode_hex) {
			off += libblake_blake224_update(&state, &buf[off], len - off);
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
			return -1;
		}
	}
	req = libblake_blake224_digest_get_required_input_size(len, 0, NULL);
	if (req > size)
		buf = erealloc(buf, size);
	libblake_blake224_digest(&state, buf, len, 0, NULL, hash);
	*hash_lenp = LIBBLAKE_BLAKE224_OUTPUT_SIZE;
	free(buf);
	return 0;
}

static int
hash_file_blake256(int fd, const char *fname, int decode_hex, unsigned char hash[], size_t *hash_lenp)
{
	struct libblake_blake256_state state;
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0;
	size_t off = 0;
	size_t req;
	ssize_t r;
	int ok;
	libblake_blake256_init(&state);
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
			return -1;
		}
		len += (size_t)r;
		if (!decode_hex) {
			off += libblake_blake256_update(&state, &buf[off], len - off);
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
			return -1;
		}
	}
	req = libblake_blake256_digest_get_required_input_size(len, 0, NULL);
	if (req > size)
		buf = erealloc(buf, size);
	libblake_blake256_digest(&state, buf, len, 0, NULL, hash);
	*hash_lenp = LIBBLAKE_BLAKE256_OUTPUT_SIZE;
	free(buf);
	return 0;
}

static int
hash_file_blake384(int fd, const char *fname, int decode_hex, unsigned char hash[], size_t *hash_lenp)
{
	struct libblake_blake384_state state;
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0;
	size_t off = 0;
	size_t req;
	ssize_t r;
	int ok;
	libblake_blake384_init(&state);
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
			return -1;
		}
		len += (size_t)r;
		if (!decode_hex) {
			off += libblake_blake384_update(&state, &buf[off], len - off);
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
			return -1;
		}
	}
	req = libblake_blake384_digest_get_required_input_size(len, 0, NULL);
	if (req > size)
		buf = erealloc(buf, size);
	libblake_blake384_digest(&state, buf, len, 0, NULL, hash);
	*hash_lenp = LIBBLAKE_BLAKE384_OUTPUT_SIZE;
	free(buf);
	return 0;
}

static int
hash_file_blake512(int fd, const char *fname, int decode_hex, unsigned char hash[], size_t *hash_lenp)
{
	struct libblake_blake512_state state;
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0;
	size_t off = 0;
	size_t req;
	ssize_t r;
	int ok;
	libblake_blake512_init(&state);
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
			return -1;
		}
		len += (size_t)r;
		if (!decode_hex) {
			off += libblake_blake512_update(&state, &buf[off], len - off);
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
			return -1;
		}
	}
	req = libblake_blake512_digest_get_required_input_size(len, 0, NULL);
	if (req > size)
		buf = erealloc(buf, size);
	libblake_blake512_digest(&state, buf, len, 0, NULL, hash);
	*hash_lenp = LIBBLAKE_BLAKE512_OUTPUT_SIZE;
	free(buf);
	return 0;
}

static int
parse_fd(const char *name)
{
	long int num;
	char *end;
	if (!isdigit(*name))
		return -1;
	errno = 0;
	num = strtol(name, &end, 10);
	if (num > INT_MAX || *end || errno)
		return -1;
	return (int)num;
}

static int
open_file(const char *path, int *closep)
{
	int fd = -1;

	*closep = 0;

	if (!strcmp(path, "-"))
		fd = STDIN_FILENO;
	else if (!strcmp(path, "/dev/stdin"))
		fd = STDIN_FILENO;
	else if (!strcmp(path, "/dev/stdout"))
		fd = STDOUT_FILENO;
	else if (!strcmp(path, "/dev/stderr"))
		fd = STDERR_FILENO;
	else if (!strncmp(path, "/dev/fd/", sizeof("/dev/fd/") - 1))
		fd = parse_fd(&path[sizeof("/dev/fd/") - 1]);
	else if (!strncmp(path, "/proc/self/fd/", sizeof("/proc/self/fd/") - 1))
		fd = parse_fd(&path[sizeof("/proc/self/fd/") - 1]);

	if (fd < 0) {
		fd = open(path, O_RDONLY);
		if (fd < 0)
			return -1;
		*closep = 1;
	}

	return fd;
}

static int
hash_file(const char *path, int length, int decode_hex, unsigned char hash[], size_t *hash_lenp)
{
	int ret, fd, close_fd;

	fd = open_file(path, &close_fd);
	if (fd < 0) {
		fprintf(stderr, "%s: %s: %s\n", argv0, path, strerror(errno));
		return -1;
	}

	if (length == 224)
		ret = hash_file_blake224(fd, path, decode_hex, hash, hash_lenp);
	else if (length == 256)
		ret = hash_file_blake256(fd, path, decode_hex, hash, hash_lenp);
	else if (length == 384)
		ret = hash_file_blake384(fd, path, decode_hex, hash, hash_lenp);
	else if (length == 512)
		ret = hash_file_blake512(fd, path, decode_hex, hash, hash_lenp);
	else
		abort();

	if (close_fd)
		close(fd);
	return ret;
}

static int
hash_and_print(const char *path, int length, int decode_hex, char newline, int output_case)
{
	unsigned char hash[LIBBLAKE_BLAKE512_OUTPUT_SIZE];
	char hex[LIBBLAKE_BLAKE512_OUTPUT_SIZE * 2 + 1];
	size_t hash_len;

	if (hash_file(path, length, decode_hex, hash, &hash_len))
		return -1;

	if (output_case < 0) {
		fwrite(hash, 1, hash_len, stdout);
	} else {
		libblake_encode_hex(hash, hash_len, hex, output_case);
		printf("%s  %s%c", hex, path, newline);
	}

	return 0;
}

static int
check_and_print_file(const char *path, int length, int decode_hex, char *expected)
{
	unsigned char hash[LIBBLAKE_BLAKE512_OUTPUT_SIZE];
	int r, fd, close_fd;

	fd = open_file(path, &close_fd);
	if (fd < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "%s: %s: %s\n", argv0, path, strerror(errno));
	missing:
		printf("%s: Missing\n", path);
		return -1;
	}

	if (length == 224)
		r = hash_file_blake224(fd, path, decode_hex, hash, &(size_t){0});
	else if (length == 256)
		r = hash_file_blake256(fd, path, decode_hex, hash, &(size_t){0});
	else if (length == 384)
		r = hash_file_blake384(fd, path, decode_hex, hash, &(size_t){0});
	else if (length == 512)
		r = hash_file_blake512(fd, path, decode_hex, hash, &(size_t){0});
	else
		abort();

	if (close_fd)
		close(fd);

	if (r < 0)
		goto missing;

	libblake_decode_hex(expected, (size_t)length / 4, expected, &(int){0});
	if (!memcmp(hash, expected, (size_t)length / 8)) {
		printf("%s: OK\n", path);
		return 0;
	} else {
		printf("%s: Fail\n", path);
		return -1;
	}
}

static int
check_and_print(const char *path, int length, int decode_hex, char newline)
{
	int fd, close_fd, status = 0;
	char *buf = NULL;
	size_t size = 0;
	size_t len = 0;
	ssize_t r;
	size_t i, j, k;

	fd = open_file(path, &close_fd);
	if (fd < 0) {
		fprintf(stderr, "%s: %s: %s\n", argv0, path, strerror(errno));
		exit(2);
	}

	for (;;) {
		if (len == size)
			buf = erealloc(buf, size += 8 << 10);
		r = read(fd, &buf[len], size - len);
		if (r > 0) {
			len += (size_t)r;
		} else if (!r) {
			break;
		} else if (errno == EINTR) {
			continue;
		} else {
			fprintf(stderr, "%s: %s: %s\n", argv0, path, strerror(errno));
			exit(2);
		}
	}
	buf = erealloc(buf, len + 1);
	buf[len] = '\0';

	if (newline) {
		for (i = 0; i < len; i = k + 1) {
			while (isspace(buf[i]))
				i++;
			for (j = i; j - i < (size_t)length / 4; j++)
				if (!isxdigit(buf[j]))
					goto corrupt;
			if (j == len || !isblank(buf[j]))
				goto corrupt;
			buf[j] = '\0';
			j++;
			while (isblank(buf[j]))
				j++;
			if (!buf[j])
				goto corrupt;
			for (k = j; buf[k] && buf[k] != newline;)
				k++;
			buf[k] = '\0';
			status |= check_and_print_file(&buf[j], length, decode_hex, &buf[i]);
		}
	} else {
		for (i = 0; i < len; i = k + 1) {
			for (j = i; j - i < (size_t)length / 4; j++)
				if (!isxdigit(buf[j]))
					goto corrupt;
			if (buf[j + 0] != ' ' || buf[j + 1] != ' ')
				goto corrupt;
			buf[j] = '\0';
			j += 2;
			k = j + strlen(&buf[j]);
			status |= check_and_print_file(&buf[j], length, decode_hex, &buf[i]);
		}
	}

	if (close_fd)
		close(fd);
	return status;

corrupt:
	fprintf(stderr, "%s: %s: invalid file content\n", argv0, path);
	exit(2);
}

int
main(int argc, char *argv[])
{
	int flag_check = 0;
	int flag_binary = 0;
	int flag_lower = 0;
	int flag_upper = 0;
	int flag_hex = 0;
	int flag_zero = 0;
	int length;

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
			status |= -check_and_print("-", length, flag_hex, newline);
		} else {
			for (; *argv; argv++)
				status |= -check_and_print(*argv, length, flag_hex, newline);
		}
	} else {
		output_case = flag_binary ? -1 : flag_upper;
		if (!argc) {
			status |= -hash_and_print("-", length, flag_hex, newline, output_case);
		} else {
			for (; *argv; argv++)
				status |= -hash_and_print(*argv, length, flag_hex, newline, output_case);
		}
	}

	if (fflush(stdout) || ferror(stdout) || fclose(stdout)) {
		fprintf(stderr, "%s: %s\n", argv0, strerror(errno));
		return 2;
	}
	return status;
}
