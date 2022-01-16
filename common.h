/* See LICENSE file for copyright and license details. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <libblake.h>

#include "arg.h"

/* common.c */
void *erealloc(void *ptr, size_t n);
void *emalloc(size_t n);
int open_file(const char *path, int *closep);
int check_and_print(const char *path, size_t hashlen, int decode_hex, char newline);
int hash_and_print(const char *path, size_t hashlen, int decode_hex, char newline, int output_case);

/* *sum.c */
int hash_fd(int fd, const char *fname, int decode_hex, unsigned char hash[]);
