#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#include <libblake.h> /* for hexadecimal encoding */

#define ERROR(...) (fprintf(stderr, __VA_ARGS__), exit(1))

static char *
read_file(const char *path)
{
	int fd;
	ssize_t r;
	size_t len = 0;
	size_t size = 0;
	char *buf = NULL;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		ERROR("Internal test error, while opening %s: %s\n", path, strerror(errno)); /* $covered$ */

	for (;;) {
		if (len == size) {
			buf = realloc(buf, (size += 8192) + 1);
			if (!buf)
				ERROR("Internal test error, while reading %s: %s\n", path, strerror(ENOMEM)); /* $covered$ */
		}
		r = read(fd, &buf[len], size - len);
		if (!r)
			break;
		if (r < 0)
			ERROR("Internal test error, while reading %s: %s\n", path, strerror(errno)); /* $covered$ */
		len += (size_t)r;
	}

	if (memchr(buf, 0, len))
		ERROR("Internal test error: file %s contains NUL byte\n", path); /* $covered$ */
	buf[len] = '\0';

	close(fd);
	return buf;
}

static int
check_kat_file(const char *path, const char *algname, void (*hash_function)(unsigned char **msg, size_t msglen, size_t *msgsize,
                                                                            unsigned char **key, size_t keylen, size_t *keysize,
                                                                            const unsigned char *hash, size_t hashlen,
                                                                            unsigned char **out, size_t *outlen, size_t *outsize,
                                                                            size_t testno, size_t test_lineno, const char *path))
{
	char *data = read_file(path);
	size_t lineno = 1;
	size_t testno = 1;
	size_t test_lineno = lineno;
	char *in_line = NULL;
	char *key_line = NULL;
	char *hash_line = NULL;
	char *line;
	unsigned char *in_bin = NULL;
	unsigned char *key_bin = NULL;
	unsigned char *hash_bin = NULL;
	size_t in_size = 0;
	size_t key_size = 0;
	size_t hash_size = 0;
	size_t in_len = 0;
	size_t key_len = 0;
	size_t hash_len = 0;
	int failed = 0;
	int valid;
	unsigned char *out = NULL;
	size_t out_len;
	size_t out_size = 0;
	char *out_text = NULL;
	size_t out_text_size = 0;

	for (line = data; *line; lineno++) {
		if (!strncmp(line, "in:", sizeof("in:") - 1)) {
			if (in_line)
				ERROR("Internal test error, at line %zu in file %s: test contains multiple 'in:'\n", lineno, path); /* $covered$ */
			in_line = line;

		} else if (!strncmp(line, "key:", sizeof("key:") - 1)) {
			if (key_line)
				ERROR("Internal test error, at line %zu in file %s: test contains multiple 'key:'\n", lineno, path); /* $covered$ */
			key_line = line;

		} else if (!strncmp(line, "hash:", sizeof("hash:") - 1)) {
			if (hash_line)
				ERROR("Internal test error, at line %zu in file %s: test contains multiple 'hash:'\n", lineno, path); /* $covered$ */
			hash_line = line;

		} else if (*line == '\n') {
			if (!in_line && !key_line && !hash_line)
				continue; /* $covered$ */
			if (!in_line || !key_line || !hash_line)
				ERROR("Internal test error, at line %zu in file %s: test is incomplete\n", lineno, path); /* $covered$ */

			in_line += sizeof("in:") - 1;
			key_line += sizeof("key:") - 1;
			hash_line += sizeof("hash:") - 1;
			while (isspace(*in_line))
				in_line++;
			while (isspace(*key_line))
				key_line++;
			while (isspace(*hash_line))
				hash_line++;

			in_len = strlen(in_line);
			key_len = strlen(key_line);
			hash_len = strlen(hash_line);
			if (in_len % 2 || key_len % 2 || hash_len % 2)
				ERROR("Internal test error: corrupted test at line %zu in file %s\n", test_lineno, path); /* $covered$ */
			in_len /= 2;
			key_len /= 2;
			hash_len /= 2;
			if (in_len > in_size) {
				in_size = in_len;
				in_bin = realloc(in_bin, in_size);
				if (!in_bin)
					ERROR("Internal test error: %s\n", strerror(ENOMEM)); /* $covered$ */
			}
			if (key_len > key_size) {
				key_size = key_len;
				key_bin = realloc(key_bin, key_size);
				if (!key_bin)
					ERROR("Internal test error: %s\n", strerror(ENOMEM)); /* $covered$ */
			}
			if (hash_len > hash_size) {
				hash_size = hash_len;
				hash_bin = realloc(hash_bin, hash_size);
				if (!hash_bin)
					ERROR("Internal test error: %s\n", strerror(ENOMEM)); /* $covered$ */
			}
			if (libblake_decode_hex(in_line, in_len * 2, in_bin, &valid) != in_len || !valid ||
			    libblake_decode_hex(key_line, key_len * 2, key_bin, &valid) != key_len || !valid ||
			    libblake_decode_hex(hash_line, hash_len * 2, hash_bin, &valid) != hash_len || !valid)
				ERROR("Internal test error: corrupted test at line %zu in file %s\n", test_lineno, path); /* $covered$ */

			hash_function(&in_bin, in_len, &in_size, &key_bin, key_len, &key_size, hash_bin,
			              hash_len, &out, &out_len, &out_size, testno, test_lineno, path);

			if (out_len != hash_len || memcmp(out, hash_bin, hash_len)) {
				/* $covered{$ */
				if (out_text_size < out_len * 2 + 1) {
					out_text_size = out_len * 2 + 1;
					out_text = realloc(out_text, out_text_size);
					if (!out_text)
						ERROR("Internal test error: %s\n", strerror(ENOMEM));
				}
				libblake_encode_hex(out, out_len, out_text, 0);
				fprintf(stderr,
				        "%s failed for test %zu at line %zu in file %s:\n"
				        "\tMessage:  0x%s (%zu %s)\n"
				        "\tKey:      0x%s (%zu %s)\n"
				        "\tResult:   0x%s (%zu %s)\n"
				        "\tExpected: 0x%s (%zu %s)\n"
				        "\n",
				        algname, testno, test_lineno, path,
				        in_line, in_len, in_len == 1 ? "byte" : "bytes",
				        key_line, key_len, key_len == 1 ? "byte" : "bytes",
				        out_text, out_len, out_len == 1 ? "byte" : "bytes",
				        hash_line, hash_len, hash_len == 1 ? "byte" : "bytes");
				failed = 1;
				/* $covered}$ */
			}

			in_line = NULL;
			key_line = NULL;
			hash_line = NULL;
			testno += 1;
			test_lineno = lineno + 1;
			line++;
			continue;

		} else {
			ERROR("Internal test error, at line %zu in file %s: unrecognised line\n", lineno, path); /* $covered$ */
		}

		line = strchr(line, '\n');
		if (!line)
			ERROR("Internal test error: file %s is not new-line terminated\n", path); /* $covered$ */
		*line++ = '\0';
	}

	free(in_bin);
	free(key_bin);
	free(hash_bin);
	free(out_text);
	free(out);
	free(data);
	return failed;
}


static void
hashx(unsigned char **msg, size_t msglen, size_t *msgsize,
      unsigned char **key, size_t keylen, size_t *keysize,
      const unsigned char *hash, size_t hashlen,
      unsigned char **out, size_t *outlen, size_t *outsize,
      size_t testno, size_t test_lineno, const char *path,
      const char *const argv[])
{
	pid_t pid;
	int input_pipe[2];
	int output_pipe[2];
	size_t off;
	ssize_t r;
	int status;

	if (keylen) {
		/* KEY OPTION IS NOT YET IMPLEMENTED */
		*outlen = hashlen;
		if (*outsize < hashlen) {
			*outsize = hashlen;
			*out = realloc(*out, *outsize);
			if (!*out)
				ERROR("Internal test error: %s\n", strerror(ENOMEM)); /* $covered$ */
		}
		memcpy(*out, hash, hashlen);
		return;
	}

	if (pipe(input_pipe) || pipe(output_pipe))
		ERROR("Internal test error: %s\n", strerror(errno)); /* $covered$ */

	pid = fork();
	if (pid < 0)
		ERROR("Internal test error: %s\n", strerror(errno)); /* $covered$ */

	if (!pid) {
		/* $covered{$ */
		close(input_pipe[1]);
		close(output_pipe[0]);
		if (input_pipe[0] != STDIN_FILENO) {
			if (dup2(input_pipe[0], STDIN_FILENO) != STDIN_FILENO)
				ERROR("Internal test error: %s\n", strerror(errno));
			close(input_pipe[0]);
		}
		if (output_pipe[1] != STDOUT_FILENO) {
			if (dup2(output_pipe[1], STDOUT_FILENO) != STDOUT_FILENO)
				ERROR("Internal test error: %s\n", strerror(errno));
			close(output_pipe[1]);
		}
		execv(argv[0], (void *const)argv);
		ERROR("Internal test error: %s\n", strerror(errno));
		/* $covered}$ */

	} else {
		close(input_pipe[0]);
		close(output_pipe[1]);
		for (off = 0; off < msglen; off += (size_t)r) {
			r = write(input_pipe[1], &(*msg)[off], msglen - off);
			if (r < 0)
				ERROR("Internal test error: %s\n", strerror(errno)); /* $covered$ */
		}
		if (close(input_pipe[1]))
			ERROR("Internal test error: %s\n", strerror(errno)); /* $covered$ */
		for (*outlen = 0;;) {
			if (*outlen == *outsize) {
				*out = realloc(*out, *outsize += 512);
				if (!*out)
					ERROR("Internal test error: %s\n", strerror(ENOMEM)); /* $covered$ */
			}
			r = read(output_pipe[0], &(*out)[*outlen], *outsize - *outlen);
			if (r <= 0) {
				if (!r)
					break;
				ERROR("Internal test error: %s\n", strerror(errno)); /* $covered$ */
			}
			*outlen += (size_t)r;
		}
		close(output_pipe[0]);
		if (waitpid(pid, &status, 0) != pid)
			ERROR("Internal test error: %s\n", strerror(errno)); /* $covered$ */
		if (status)
			exit(1); /* $covered$ */
	}
}

static void
hash_blake2s(unsigned char **msg, size_t msglen, size_t *msgsize,
             unsigned char **key, size_t keylen, size_t *keysize,
             const unsigned char *hash, size_t hashlen,
             unsigned char **out, size_t *outlen, size_t *outsize,
             size_t testno, size_t test_lineno, const char *path)
{
	char out_bits_str[3 * sizeof(size_t) + 1];
	sprintf(out_bits_str, "%zu", hashlen * 8);
	hashx(msg, msglen, msgsize,
	      key, keylen, keysize,
	      hash, hashlen,
	      out, outlen, outsize,
	      testno, test_lineno, path,
	      (const char *const[]){"./b2sum", "-Bs", "-l", out_bits_str, NULL});
}

static void
hash_blake2b(unsigned char **msg, size_t msglen, size_t *msgsize,
             unsigned char **key, size_t keylen, size_t *keysize,
             const unsigned char *hash, size_t hashlen,
             unsigned char **out, size_t *outlen, size_t *outsize,
             size_t testno, size_t test_lineno, const char *path)
{
	char out_bits_str[3 * sizeof(size_t) + 1];
	sprintf(out_bits_str, "%zu", hashlen * 8);
	hashx(msg, msglen, msgsize,
	      key, keylen, keysize,
	      hash, hashlen,
	      out, outlen, outsize,
	      testno, test_lineno, path,
	      (const char *const[]){"./b2sum", "-B", "-l", out_bits_str, NULL});
}

static void
hash_blake2xs(unsigned char **msg, size_t msglen, size_t *msgsize,
              unsigned char **key, size_t keylen, size_t *keysize,
              const unsigned char *hash, size_t hashlen,
              unsigned char **out, size_t *outlen, size_t *outsize,
              size_t testno, size_t test_lineno, const char *path)
{
	char out_bits_str[3 * sizeof(size_t) + 1];
	sprintf(out_bits_str, "%zu", hashlen * 8);
	hashx(msg, msglen, msgsize,
	      key, keylen, keysize,
	      hash, hashlen,
	      out, outlen, outsize,
	      testno, test_lineno, path,
	      (const char *const[]){"./b2sum", "-Bs", "-X", out_bits_str, NULL});
}

static void
hash_blake2xb(unsigned char **msg, size_t msglen, size_t *msgsize,
              unsigned char **key, size_t keylen, size_t *keysize,
              const unsigned char *hash, size_t hashlen,
              unsigned char **out, size_t *outlen, size_t *outsize,
              size_t testno, size_t test_lineno, const char *path)
{
	char out_bits_str[3 * sizeof(size_t) + 1];
	sprintf(out_bits_str, "%zu", hashlen * 8);
	hashx(msg, msglen, msgsize,
	      key, keylen, keysize,
	      hash, hashlen,
	      out, outlen, outsize,
	      testno, test_lineno, path,
	      (const char *const[]){"./b2sum", "-B", "-X", out_bits_str, NULL});
}

int
main(void)
{
	int failed = 0;

	/* TODO test bsum */

	failed |= check_kat_file("kat/blake2s", "BLAKE2s", &hash_blake2s);
	failed |= check_kat_file("kat/blake2b", "BLAKE2b", &hash_blake2b);
	failed |= check_kat_file("kat/blake2xs", "BLAKE2Xs", &hash_blake2xs);
	failed |= check_kat_file("kat/blake2xb", "BLAKE2Xb", &hash_blake2xb);
	/* TODO test b2sum -cLUxz, implicit -L, restrictions on -l/-X, and file operand */

	return failed;
}
