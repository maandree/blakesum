/* See LICENSE file for copyright and license details. */
#include "common.h"

void *
erealloc(void *ptr, size_t n)
{
	ptr = realloc(ptr, n);
	if (!ptr) {
		fprintf(stderr, "%s: %s\n", argv0, strerror(errno));
		exit(2);
	}
	return ptr;
}

void *
emalloc(size_t n)
{
	void *ptr = malloc(n);
	if (!ptr) {
		fprintf(stderr, "%s: %s\n", argv0, strerror(errno));
		exit(2);
	}
	return ptr;
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

int
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
check_and_print_file(const char *path, size_t hashlen, int decode_hex, char *expected)
{
	unsigned char *hash;
	int r, fd, close_fd;

	fd = open_file(path, &close_fd);
	if (fd < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "%s: %s: %s\n", argv0, path, strerror(errno));
	missing:
		printf("%s: Missing\n", path);
		return -1;
	}

	hash = hashlen ? emalloc(hashlen / 8) : NULL;
	r = hash_fd(fd, path, decode_hex, hash);

	if (close_fd)
		close(fd);

	if (r < 0) {
		free(hash);
		goto missing;
	}

	libblake_decode_hex(expected, hashlen / 4, expected, &(int){0});
	if (!memcmp(hash, expected, hashlen / 8)) {
		free(hash);
		printf("%s: OK\n", path);
		return 0;
	} else {
		free(hash);
		printf("%s: Fail\n", path);
		return -1;
	}
}

int
check_and_print(const char *path, size_t hashlen, int decode_hex, char newline)
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
			for (j = i; j - i < hashlen / 4; j++)
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
			status |= check_and_print_file(&buf[j], hashlen, decode_hex, &buf[i]);
		}
	} else {
		for (i = 0; i < len; i = k + 1) {
			for (j = i; j - i < hashlen / 4; j++)
				if (!isxdigit(buf[j]))
					goto corrupt;
			if (buf[j + 0] != ' ' || buf[j + 1] != ' ')
				goto corrupt;
			buf[j] = '\0';
			j += 2;
			k = j + strlen(&buf[j]);
			status |= check_and_print_file(&buf[j], hashlen, decode_hex, &buf[i]);
		}
	}

	if (close_fd)
		close(fd);
	return status;

corrupt:
	fprintf(stderr, "%s: %s: invalid file content\n", argv0, path);
	exit(2);
}

static int
hash_file(const char *path, int decode_hex, unsigned char hash[])
{
	int ret, fd, close_fd;

	fd = open_file(path, &close_fd);
	if (fd < 0) {
		fprintf(stderr, "%s: %s: %s\n", argv0, path, strerror(errno));
		return -1;
	}

	ret = hash_fd(fd, path, decode_hex, hash);

	if (close_fd)
		close(fd);
	return ret;
}

int
hash_and_print(const char *path, size_t hashlen, int decode_hex, char newline, int output_case)
{
	unsigned char *hash;
	char *hex;

	hash = hashlen ? emalloc(hashlen / 8) : 0;
	hex = emalloc(hashlen / 4 + 1);

	if (hash_file(path, decode_hex, hash)) {
		free(hash);
		free(hex);
		return -1;
	}

	if (output_case < 0) {
		fwrite(hash, 1, hashlen / 8, stdout);
	} else {
		libblake_encode_hex(hash, hashlen / 8, hex, output_case);
		printf("%s  %s%c", hex, path, newline);
	}

	free(hash);
	free(hex);
	return 0;
}

static void
parse_salt_or_pepper(uint_least8_t *out, const char *s, size_t required_length, const char *type)
{
	size_t i;

	for (i = 0; i < required_length; i++, s = &s[2]) {
		if (!s[0] || !s[1])
			goto too_short;
		if (!isxdigit(s[0]) || !isxdigit(s[1]))
			goto not_hexadecimal;

		out[i] = (uint_least8_t)((((s[0] & 15) + (s[0] > '9' ? 9 : 0)) << 4) |
		                           (s[1] & 15) + (s[1] > '9' ? 9 : 0));
	}

	if (*s)
		goto too_long;

	return;

not_hexadecimal:
	fprintf(stderr, "%s: specified %s contains non-hexadecimal-digit character\n", argv0, type);
	exit(2);

too_short:
	fprintf(stderr, "%s: specified %s is shorter than expected, should be %zu hexadecimal digits\n",
	                argv0, type, required_length * 2);
	exit(2);

too_long:
	fprintf(stderr, "%s: specified %s is longer than expected, should be %zu hexadecimal digits\n",
	                argv0, type, required_length * 2);
	exit(2);
}

void
parse_salt(uint_least8_t *salt, const char *s, size_t required_length)
{
	parse_salt_or_pepper(salt, s, required_length, "salt");
}

void
parse_pepper(uint_least8_t *pepper, const char *s, size_t required_length)
{
	parse_salt_or_pepper(pepper, s, required_length, "pepper");
}

size_t
parse_key(uint_least8_t *key, const char *s, size_t maximum_length)
{
	size_t i;

	if (!*s)
		goto empty_key;

	for (i = 0; i < maximum_length; i++, s = &s[2]) {
		if (!s[0])
			break;
		if (!s[1])
			goto odd_length;
		if (!isxdigit(s[0]) || !isxdigit(s[1]))
			goto not_hexadecimal;

		key[i] = (uint_least8_t)((((s[0] & 15) + (s[0] > '9' ? 9 : 0)) << 4) |
		                           (s[1] & 15) + (s[1] > '9' ? 9 : 0));
	}

	if (*s)
		goto too_long;

	return i;

empty_key:
	fprintf(stderr, "%s: specified key is empty\n", argv0);
	exit(2);

odd_length:
	fprintf(stderr, "%s: specified key contains an odd number of hexadecimal digits\n", argv0);
	exit(2);

not_hexadecimal:
	fprintf(stderr, "%s: specified key contains non-hexadecimal-digit character\n", argv0);
	exit(2);

too_long:
	fprintf(stderr, "%s: specified key is longer than allowed, should be at most %zu hexadecimal digits\n",
	                argv0, maximum_length * 2);
	exit(2);
}
