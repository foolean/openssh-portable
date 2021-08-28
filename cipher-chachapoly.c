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

#if defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"

#include "thpool.h" /** needed for Pithikos Pool Thread */
#include "chacha.h"
#include <math.h>

//MIN Function
#define MIN(a,b) (((a)<(b))?(a):(b))

struct chachapoly_ctx {
	struct chacha_ctx main_ctx, header_ctx;
};

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
	return ctx;
}

void
chachapoly_free(struct chachapoly_ctx *cpctx)
{
	freezero(cpctx, sizeof(*cpctx));
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
	const u_char one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
	int r = SSH_ERR_INTERNAL_ERROR;
	threadpool thpool;
	u_int num_threads = 8;

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

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);

	//creating thread pool only if more than 64*8 bytes worth of data
	if (((len / CHACHA_BLOCKLEN) > num_threads)) {
		//initializing thread pool
		if ((thpool = thpool_init(num_threads))) {
			r = SSH_ERR_THPOOL_INIT; //thread pool failed to initialize
			goto out;
		}
		
		//copying initialization vector 
		struct chacha_ctx *chacha_iv = malloc(sizeof(struct chacha_ctx));
		if (!chacha_iv) {
			r = SSH_ERR_THPOOL_INIT; //malloc error
			goto out;
		}
		//copy the input array w 16 u_int elems
		memcpy(chacha_iv->input, (&ctx->main_ctx)->input, (16*sizeof(u_int)));
		
		u_int curr_blk = 0;
		u_int remaining_bytes = len;
		while (remaining_bytes) {
			chacha_args *curr_args = malloc(sizeof(chacha_args));
			if (!curr_args) {
				r = SSH_ERR_THPOOL_INIT; //malloc error
				goto out;
			}
			/**
			 * IV already has blk counter set to 1;
			 * we increment blk counter to correct blk number for each blk
			 */
			memcpy(curr_args->x, chacha_iv->input, (16*sizeof(u_int)));
			curr_args->m = src + aadlen + (curr_blk * CHACHA_BLOCKLEN);
			curr_args->c = dest + aadlen + (curr_blk * CHACHA_BLOCKLEN);
			curr_args->blk_num = curr_blk;
			curr_args->bytes = MIN(remaining_bytes, CHACHA_BLOCKLEN);
			thpool_add_work(thpool, (void*)chacha_encrypt_bytes_pool, 
							(void*)curr_args);
			
			remaining_bytes-=CHACHA_BLOCKLEN;
			curr_blk++;
		}
		
		//checks
		//assert(i == num_blocks);
		free(chacha_iv);
		thpool_destroy(thpool);
	} else {
		//proceed without prethreading
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
