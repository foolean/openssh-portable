/*	$OpenBSD: sshbuf-io.c,v 1.2 2020/01/25 23:28:06 djm Exp $ */
/*
 * Copyright (c) 2011 Damien Miller
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "atomicio.h"

/* Load a file from a fd into a buffer */
int
sshbuf_load_fd(int fd, struct sshbuf **blobp)
{
	u_char buf[4096];
	size_t len;
	struct stat st;
	int r;
	struct sshbuf *blob;

	*blobp = NULL;

	if (fstat(fd, &st) == -1)
		return SSH_ERR_SYSTEM_ERROR;
	if ((st.st_mode & (S_IFSOCK|S_IFCHR|S_IFIFO)) == 0 &&
	    st.st_size > SSHBUF_SIZE_MAX)
		return SSH_ERR_INVALID_FORMAT;
	if ((blob = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	for (;;) {
		if ((len = atomicio(read, fd, buf, sizeof(buf))) == 0) {
			if (errno == EPIPE)
				break;
			r = SSH_ERR_SYSTEM_ERROR;
			goto out;
		}
		if ((r = sshbuf_put(blob, buf, len)) != 0)
			goto out;
		if (sshbuf_len(blob) > SSHBUF_SIZE_MAX) {
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	if ((st.st_mode & (S_IFSOCK|S_IFCHR|S_IFIFO)) == 0 &&
	    st.st_size != (off_t)sshbuf_len(blob)) {
		r = SSH_ERR_FILE_CHANGED;
		goto out;
	}
	/* success */
	*blobp = blob;
	blob = NULL; /* transferred */
	r = 0;
 out:
	explicit_bzero(buf, sizeof(buf));
	sshbuf_free(blob);
	return r;
}

int
sshbuf_load_file(const char *path, struct sshbuf **bufp)
{
	int r, fd, oerrno;

	*bufp = NULL;
	if ((fd = open(path, O_RDONLY)) == -1)
		return SSH_ERR_SYSTEM_ERROR;
	if ((r = sshbuf_load_fd(fd, bufp)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	if (r != 0)
		errno = oerrno;
	return r;
}

int
sshbuf_write_file(const char *path, struct sshbuf *buf)
{
	int fd, oerrno;

	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		return SSH_ERR_SYSTEM_ERROR;
	if (atomicio(vwrite, fd, sshbuf_mutable_ptr(buf),
	    sshbuf_len(buf)) != sshbuf_len(buf) || close(fd) != 0) {
		oerrno = errno;
		close(fd);
		unlink(path);
		errno = oerrno;
		return SSH_ERR_SYSTEM_ERROR;
	}
	return 0;
}

int
sshbuf_read(int fd, struct sshbuf *buf, size_t maxlen, size_t *rlen)
{
	int r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	if (rlen != NULL)
		*rlen = 0;
	if ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		return r;
	rr = read(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	if (rr > 0 && (adjust = maxlen - rr) > 0) {
		if ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			return SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	if (rr < 0) {
		errno = oerrno;
		return SSH_ERR_SYSTEM_ERROR;
	} else if (rr == 0) {
		errno = EPIPE;
		return SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	if (rlen != NULL)
		*rlen = (size_t)rr;
	return 0;
}

