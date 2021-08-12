/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#include "includes.h"

#include "chacha.h"

#include "omp.h"

/* $OpenBSD: chacha.c,v 1.1 2013/11/21 00:45:44 djm Exp $ */

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct chacha_ctx chacha_ctx;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void
chacha_keysetup(chacha_ctx *x,const u8 *k,u32 kbits)
{
  const char *constants;

  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[1] = U8TO32_LITTLE(constants + 4);
  x->input[2] = U8TO32_LITTLE(constants + 8);
  x->input[3] = U8TO32_LITTLE(constants + 12);
}

void
chacha_ivsetup(chacha_ctx *x, const u8 *iv, const u8 *counter)
{
  // block counter
  x->input[12] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 0);
  x->input[13] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 4);
  // nonce
  x->input[14] = U8TO32_LITTLE(iv + 0);
  x->input[15] = U8TO32_LITTLE(iv + 4);
}

void
chacha_encrypt_bytes(chacha_ctx *x,const u8 *m,u8 *c,u32 bytes)
{
  // u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  // u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  u32 j[16];
  u8 *ctarget = NULL;
  u8 tmp[64];
  u_int i, finished = 0;
  u32 b, numChunks = (bytes+63)/64;
  u8 *msg, *dest;

  if (!bytes) return;
  // j[i] is copy of input to add with result of round function
  for (i = 0; i < 16; i++) j[i] = x->input[i];

  // infinite loop to process data in 64-byte chunks
  #pragma omp parallel for private(dest, msg) schedule(dynamic)
  {
  for (b = 0; b < numChunks; b++) {
    u32 block[16];
    u32 bytesLeft = bytes - b*64;
    msg = m + b*64;
    dest = c + b*64;

    if (bytesLeft < 64) { // last 64-byte chunk
      for (i = 0;i < bytesLeft;++i) tmp[i] = m[i]; // create copy of end of msg
      m = tmp;
      ctarget = c;
      c = tmp;
    }
    // copy input into block
    for (i = 0; i < 16; i++) block[i] = j[i];

    // set block counter accordingly
    for (i = 0; i < b; i++) {
      // add one to block counter
      block[12] = PLUSONE(block[12]);
      if (!block[12]) {
        block[13] = PLUSONE(block[13]);
        /* stopping at 2^70 bytes per nonce is user's responsibility */
      }
    }

    // round function
    for (i = 20;i > 0;i -= 2) { // cha cha real smooth
      QUARTERROUND( block[0], block[4], block[8],block[12])
      QUARTERROUND( block[1], block[5], block[9],block[13])
      QUARTERROUND( block[2], block[6],block[10],block[14])
      QUARTERROUND( block[3], block[7],block[11],block[15])
      QUARTERROUND( block[0], block[5],block[10],block[15])
      QUARTERROUND( block[1], block[6],block[11],block[12])
      QUARTERROUND( block[2], block[7], block[8],block[13])
      QUARTERROUND( block[3], block[4], block[9],block[14])
    }
    // add block and j
    for (i = 0; i < 16; i++) block[i] = PLUS(block[i], j[i]);

    // XOR x_i with message
    for (i = 0; i < 16; i++) block[i] = XOR(block[i],U8TO32_LITTLE(m+4*i));
    
    // output result
    for (i = 0; i < 16; i++) U32TO8_LITTLE(c+4*i, block[i]);

    // if last block
    if (bytesLeft <= 64) {
      if (bytesLeft < 64) {
        for (i = 0;i < bytesLeft;++i) ctarget[i] = c[i]; // put final part of output into output pointer
      }
      // put final block counter back into x
      x->input[12] = block[12];
      x->input[13] = block[13];
    }
  }
  }
  return;
}