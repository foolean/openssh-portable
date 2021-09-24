/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

/* $OpenBSD: cipher-chachapoly.c,v 1.9 2020/04/03 04:27:03 djm Exp $ */

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"
#include "pthread_pool.h"

#define POKE_U32_LITTLE(p, v)			\
        do { \
                const u_int32_t __v = (v); \
		((u_char *)(p))[3] = (__v >> 24) & 0xff; \
                ((u_char *)(p))[2] = (__v >> 16) & 0xff; \
                ((u_char *)(p))[1] = (__v >> 8) & 0xff; \
                ((u_char *)(p))[0] = __v & 0xff; \
        } while (0)

struct chachapoly_ctx {
	struct chacha_ctx main_ctx, header_ctx;
	const u_char *key;
	int keylen;
	int reset;
};

struct chachajob {
	u_char *dest;
	const u_char *src;
	u_int len;
	u_int offset;
	u_char blk_ctr[8];
	u_char seqbuf[8];
	struct chachapoly_ctx *ctx;
	int free_ctx;
} chachajob;

pthread_mutex_t lock;
pthread_cond_t cond;
int tcount = 0;
void *thpool = NULL;
#define MAX_JOBS 16
struct chachajob ccjob[MAX_JOBS]; /* why 16? */

struct chachapoly_ctx *
chachapoly_new(const u_char *key, u_int keylen)
{
	struct chachapoly_ctx *ctx;

	if (keylen != (32 + 32)) /* 2 x 256 bit keys */
		return NULL;
	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return NULL;
	chacha_keysetup(&ctx->main_ctx, key, 256);
	chacha_keysetup(&ctx->header_ctx, key + 32, 256);
	ctx->key = key;
	ctx->keylen = keylen;
	ctx->reset = 1;
	return ctx;
}

void
chachapoly_free(struct chachapoly_ctx *cpctx)
{
	freezero(cpctx, sizeof(*cpctx));
}

/* threaded function */
void *
chachapoly_thread_work(void *job) {
	struct chachajob *lt = (struct chachajob *)job;
	chacha_ivsetup(&lt->ctx->main_ctx, lt->seqbuf, lt->blk_ctr);	
	chacha_encrypt_bytes(&lt->ctx->main_ctx, lt->src + lt->offset, lt->dest + lt->offset, lt->len);
	return (0);
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	u_char seqbuf[8];
	const u_char one[8] = { 0, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
	int r = SSH_ERR_INTERNAL_ERROR;
	u_int chunk = 128 * 64; /* 128 cc20 blocks */

	POKE_U32_LITTLE(one, 1);

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_key, 0, sizeof(poly_key));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->main_ctx,
			     poly_key, poly_key, sizeof(poly_key));

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;

		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	/* Crypt additional data */
	if (aadlen) {
		chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/*
	   basic premise. You have an inbound 'src' and an outbound 'dest'
	   src has the enclear data and dest holds the crypto data. Take the
	   src data and break it down into chunks and process each of those chunk
	   in parallel. The resulting crypto'd chunk can then just be slotted into
	   dest at the appropriate byte location.
	 */
	if (len >= chunk) { /* if the length of the inbound datagram is less than */
        		    /* the chunk size don't bother with threading. */
		u_int bufptr = 0; /* tracks where we are in the buffer */
		int i = 0;
		if (thpool == NULL) {
			fprintf(stderr, "initializing thread pool\n");
			thpool=pool_start(chachapoly_thread_work, 4);
		}
		/* initialize contexts for threads */
		/* if the key is changed we need to reinitialize the keys */
		if (ctx->reset == 1) {		
			for (int i = 0; i < MAX_JOBS; i++) {
				//pthread_mutex_init(&thread[i].tlock, NULL);
				fprintf(stderr, "Initializing ccjob[%d].ctx (keylen: %d]\n", i, ctx->keylen);
				ccjob[i].ctx = chachapoly_new(ctx->key, ctx->keylen);
			}
			ctx->reset = 0; /*reset complete */
		}
		/* this actually determines the length of each chunk
                 * and the offset for the jobs. We pass pointers to
                 * src and dest. The threadpool slots everything in where
                 * it needs to go using the length and offset */
		while (bufptr < len) {
			memset(ccjob[i].seqbuf, 0, sizeof(seqbuf));
			POKE_U64(ccjob[i].seqbuf, seqnr);
			POKE_U32_LITTLE(ccjob[i].blk_ctr, (bufptr/64) +1);
			/* the offset is where we read the data from src and
			 * where we put it into dest */
			ccjob[i].offset = aadlen + bufptr;
			if ((len - bufptr) >= chunk) { /* full sized chunk */
				ccjob[i].len = chunk;
				bufptr += chunk;
			} else { /* partial chunk end of buffer */
				ccjob[i].len = len-bufptr;
				bufptr = len;
			}
			ccjob[i].src = src;
			ccjob[i].dest = dest;
			pool_enqueue(thpool, &ccjob[i]);
			i++;
			if (i >= MAX_JOBS) {
				fatal("Threaded chacha tried to spawn too many jobs\n");
			}
		}
		while (pool_count(thpool)) {
			/* sit and spin while we wait for the jobs to finish*/
		}
	} else {
		chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
		chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
				     dest + aadlen, len);
	}

	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
			      poly_key);
	}
	r = 0;
out:
	explicit_bzero(expected_tag, sizeof(expected_tag));
	explicit_bzero(seqbuf, sizeof(seqbuf));
	explicit_bzero(poly_key, sizeof(poly_key));
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapoly_get_length(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[8];

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	return 0;
}

#endif /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
