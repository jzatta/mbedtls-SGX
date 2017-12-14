/*
 *  AES-NI support functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * [AES-WP] http://software.intel.com/en-us/articles/intel-advanced-encryption-standard-aes-instructions-set
 * [CLMUL-WP] http://software.intel.com/en-us/articles/intel-carry-less-multiplication-instruction-and-its-usage-for-computing-the-gcm-mode/
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_AESNI_C)

#include "mbedtls/aesni.h"

#include <string.h>

#ifndef asm
#define asm __asm
#endif

#if defined(MBEDTLS_HAVE_X86_64)


/*
 * Binutils needs to be at least 2.19 to support AES-NI instructions.
 * Unfortunately, a lot of users have a lower version now (2014-04).
 * Emit bytecode directly in order to support "old" version of gas.
 *
 * Opcodes from the Intel architecture reference manual, vol. 3.
 * We always use registers, so we don't need prefixes for memory operands.
 * Operand macros are in gas order (src, dst) as opposed to Intel order
 * (dst, src) in order to blend better into the surrounding assembly code.
 */
#define AESDEC      ".byte 0x66,0x0F,0x38,0xDE,"
#define AESDECLAST  ".byte 0x66,0x0F,0x38,0xDF,"
#define AESENC      ".byte 0x66,0x0F,0x38,0xDC,"
#define AESENCLAST  ".byte 0x66,0x0F,0x38,0xDD,"
#define AESIMC      ".byte 0x66,0x0F,0x38,0xDB,"
#define AESKEYGENA  ".byte 0x66,0x0F,0x3A,0xDF,"
#define PCLMULQDQ   ".byte 0x66,0x0F,0x3A,0x44,"

#define xmm0_xmm0   "0xC0"
#define xmm0_xmm1   "0xC8"
#define xmm0_xmm2   "0xD0"
#define xmm0_xmm3   "0xD8"
#define xmm0_xmm4   "0xE0"
#define xmm1_xmm0   "0xC1"
#define xmm1_xmm2   "0xD1"

#include <wmmintrin.h>

/* Note – the length of the output buffer is assumed to be a multiple of 16 bytes */
inline static void AES_ECB_encrypt(const unsigned char *in,  //pointer to thePLAINTEXT
                     unsigned char *out,       //pointer to the CIPHERTEXT buffer
                     int length,     //text length in bytes
                     const char *key,          //pointer to the expanded key schedule
                     int number_of_rounds) {   //number of AES rounds 10,12 or 14
    __m128i tmp;
    int i, j;
    if (length % 16) {
        length = length/16+1;
    } else{
        length = length/16;
    }
    for (i = 0; i < length; i++) {
        tmp =_mm_loadu_si128(&((__m128i*)in)[i]);
        tmp =_mm_xor_si128(tmp,((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++) {
            tmp =_mm_aesenc_si128(tmp,((__m128i*)key)[j]);
        }
        tmp =_mm_aesenclast_si128(tmp,((__m128i*)key)[j]);
        _mm_storeu_si128(&((__m128i*)out)[i],tmp);
    }
}

inline static void AES_ECB_decrypt(const unsigned char *in,  //pointer to theCIPHERTEXT
                         unsigned char *out,       //pointer to the DECRYPTED TEXT buffer
                         int length,     //text length in bytes
                         const char *key,          //pointer to the expanded key schedule
                         int number_of_rounds) {   //number of AES rounds 10,12 or 14{__m128i tmp;
    __m128i tmp;
    int i,j;
    if (length % 16) {
        length = length / 16 + 1;
    } else {
        length = length / 16;
    }
    for (i = 0; i < length; i++) {
        tmp =_mm_loadu_si128(&((__m128i*)in)[i]);
        tmp =_mm_xor_si128(tmp,((__m128i*)key)[0]);
        for (j = 1; j < number_of_rounds; j++) {
            tmp =_mm_aesdec_si128(tmp,((__m128i*)key)[j]);
        }
        tmp =_mm_aesdeclast_si128(tmp,((__m128i*)key)[j]);
        _mm_storeu_si128(&((__m128i*)out)[i],tmp);
    }
}

/*
 * AES-NI AES-ECB block en(de)cryption
 */
int mbedtls_aesni_crypt_ecb( mbedtls_aes_context *ctx,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] )
{
    if (mode == MBEDTLS_AES_ENCRYPT) {
        AES_ECB_encrypt(input, output, 16, (const char *)ctx->rk, ctx->nr);
    } else { //(mode == MBEDTLS_AES_DECRYPT)
        AES_ECB_decrypt(input, output, 16, (const char *)ctx->rk, ctx->nr);
    }
    return( 0 );
}

/*
 * GCM multiplication: c = a times b in GF(2^128)
 * Based on [CLMUL-WP] algorithms 1 (with equation 27) and 5.
 */
void mbedtls_aesni_gcm_mult( unsigned char c[16],
                     const unsigned char a[16],
                     const unsigned char b[16] )
{
    unsigned char aa[16], bb[16], cc[16];
    size_t i;

    /* The inputs are in big-endian order, so byte-reverse them */
    for( i = 0; i < 16; i++ )
    {
        aa[i] = a[15 - i];
        bb[i] = b[15 - i];
    }

    asm( "movdqu (%0), %%xmm0               \n\t" // a1:a0
         "movdqu (%1), %%xmm1               \n\t" // b1:b0

         /*
          * Caryless multiplication xmm2:xmm1 = xmm0 * xmm1
          * using [CLMUL-WP] algorithm 1 (p. 13).
          */
         "movdqa %%xmm1, %%xmm2             \n\t" // copy of b1:b0
         "movdqa %%xmm1, %%xmm3             \n\t" // same
         "movdqa %%xmm1, %%xmm4             \n\t" // same
         PCLMULQDQ xmm0_xmm1 ",0x00         \n\t" // a0*b0 = c1:c0
         PCLMULQDQ xmm0_xmm2 ",0x11         \n\t" // a1*b1 = d1:d0
         PCLMULQDQ xmm0_xmm3 ",0x10         \n\t" // a0*b1 = e1:e0
         PCLMULQDQ xmm0_xmm4 ",0x01         \n\t" // a1*b0 = f1:f0
         "pxor %%xmm3, %%xmm4               \n\t" // e1+f1:e0+f0
         "movdqa %%xmm4, %%xmm3             \n\t" // same
         "psrldq $8, %%xmm4                 \n\t" // 0:e1+f1
         "pslldq $8, %%xmm3                 \n\t" // e0+f0:0
         "pxor %%xmm4, %%xmm2               \n\t" // d1:d0+e1+f1
         "pxor %%xmm3, %%xmm1               \n\t" // c1+e0+f1:c0

         /*
          * Now shift the result one bit to the left,
          * taking advantage of [CLMUL-WP] eq 27 (p. 20)
          */
         "movdqa %%xmm1, %%xmm3             \n\t" // r1:r0
         "movdqa %%xmm2, %%xmm4             \n\t" // r3:r2
         "psllq $1, %%xmm1                  \n\t" // r1<<1:r0<<1
         "psllq $1, %%xmm2                  \n\t" // r3<<1:r2<<1
         "psrlq $63, %%xmm3                 \n\t" // r1>>63:r0>>63
         "psrlq $63, %%xmm4                 \n\t" // r3>>63:r2>>63
         "movdqa %%xmm3, %%xmm5             \n\t" // r1>>63:r0>>63
         "pslldq $8, %%xmm3                 \n\t" // r0>>63:0
         "pslldq $8, %%xmm4                 \n\t" // r2>>63:0
         "psrldq $8, %%xmm5                 \n\t" // 0:r1>>63
         "por %%xmm3, %%xmm1                \n\t" // r1<<1|r0>>63:r0<<1
         "por %%xmm4, %%xmm2                \n\t" // r3<<1|r2>>62:r2<<1
         "por %%xmm5, %%xmm2                \n\t" // r3<<1|r2>>62:r2<<1|r1>>63

         /*
          * Now reduce modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1
          * using [CLMUL-WP] algorithm 5 (p. 20).
          * Currently xmm2:xmm1 holds x3:x2:x1:x0 (already shifted).
          */
         /* Step 2 (1) */
         "movdqa %%xmm1, %%xmm3             \n\t" // x1:x0
         "movdqa %%xmm1, %%xmm4             \n\t" // same
         "movdqa %%xmm1, %%xmm5             \n\t" // same
         "psllq $63, %%xmm3                 \n\t" // x1<<63:x0<<63 = stuff:a
         "psllq $62, %%xmm4                 \n\t" // x1<<62:x0<<62 = stuff:b
         "psllq $57, %%xmm5                 \n\t" // x1<<57:x0<<57 = stuff:c

         /* Step 2 (2) */
         "pxor %%xmm4, %%xmm3               \n\t" // stuff:a+b
         "pxor %%xmm5, %%xmm3               \n\t" // stuff:a+b+c
         "pslldq $8, %%xmm3                 \n\t" // a+b+c:0
         "pxor %%xmm3, %%xmm1               \n\t" // x1+a+b+c:x0 = d:x0

         /* Steps 3 and 4 */
         "movdqa %%xmm1,%%xmm0              \n\t" // d:x0
         "movdqa %%xmm1,%%xmm4              \n\t" // same
         "movdqa %%xmm1,%%xmm5              \n\t" // same
         "psrlq $1, %%xmm0                  \n\t" // e1:x0>>1 = e1:e0'
         "psrlq $2, %%xmm4                  \n\t" // f1:x0>>2 = f1:f0'
         "psrlq $7, %%xmm5                  \n\t" // g1:x0>>7 = g1:g0'
         "pxor %%xmm4, %%xmm0               \n\t" // e1+f1:e0'+f0'
         "pxor %%xmm5, %%xmm0               \n\t" // e1+f1+g1:e0'+f0'+g0'
         // e0'+f0'+g0' is almost e0+f0+g0, ex\tcept for some missing
         // bits carried from d. Now get those\t bits back in.
         "movdqa %%xmm1,%%xmm3              \n\t" // d:x0
         "movdqa %%xmm1,%%xmm4              \n\t" // same
         "movdqa %%xmm1,%%xmm5              \n\t" // same
         "psllq $63, %%xmm3                 \n\t" // d<<63:stuff
         "psllq $62, %%xmm4                 \n\t" // d<<62:stuff
         "psllq $57, %%xmm5                 \n\t" // d<<57:stuff
         "pxor %%xmm4, %%xmm3               \n\t" // d<<63+d<<62:stuff
         "pxor %%xmm5, %%xmm3               \n\t" // missing bits of d:stuff
         "psrldq $8, %%xmm3                 \n\t" // 0:missing bits of d
         "pxor %%xmm3, %%xmm0               \n\t" // e1+f1+g1:e0+f0+g0
         "pxor %%xmm1, %%xmm0               \n\t" // h1:h0
         "pxor %%xmm2, %%xmm0               \n\t" // x3+h1:x2+h0

         "movdqu %%xmm0, (%2)               \n\t" // done
         :
         : "r" (aa), "r" (bb), "r" (cc)
         : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5" );

    /* Now byte-reverse the outputs */
    for( i = 0; i < 16; i++ )
        c[i] = cc[15 - i];

    return;
}

/*
 * Compute decryption round keys from encryption round keys
 */
void mbedtls_aesni_inverse_key( unsigned char *invkey,
                        const unsigned char *fwdkey, int nr )
{
    int i;
    __m128i *Key_Schedule = (__m128i*)fwdkey;
    __m128i *Key_ScheduleIv = (__m128i*)invkey;
    Key_ScheduleIv[0] = Key_Schedule[nr];
    for (i = 1; i < nr; i++) {
        Key_ScheduleIv[i] = _mm_aesimc_si128(Key_Schedule[nr-i]);
    }
    Key_ScheduleIv[nr] = Key_Schedule[0];
}


inline __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp1 = _mm_xor_si128 (temp1, temp2);
    return temp1;
}

inline void KEY_192_ASSIST(__m128i* temp1, __m128i * temp2, __m128i * temp3) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32 (*temp2, 0x55);
    temp4 = _mm_slli_si128 (*temp1, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    temp4 = _mm_slli_si128 (temp4, 0x4);
    *temp1 = _mm_xor_si128 (*temp1, temp4);
    *temp1 = _mm_xor_si128 (*temp1, *temp2);
    *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
    temp4 = _mm_slli_si128 (*temp3, 0x4);
    *temp3 = _mm_xor_si128 (*temp3, temp4);
    *temp3 = _mm_xor_si128 (*temp3, *temp2);
}

inline void KEY_256_ASSIST_1(__m128i* temp1,__m128i * temp2) {
    __m128i temp4;
    *temp2 =_mm_shuffle_epi32(*temp2, 0xff);
    temp4 =_mm_slli_si128 (*temp1, 0x4);
    *temp1 =_mm_xor_si128 (*temp1, temp4);
    temp4 =_mm_slli_si128 (temp4, 0x4);
    *temp1 =_mm_xor_si128 (*temp1, temp4);
    temp4 =_mm_slli_si128 (temp4, 0x4);
    *temp1 =_mm_xor_si128 (*temp1, temp4);
    *temp1 =_mm_xor_si128 (*temp1, *temp2);
}

inline void KEY_256_ASSIST_2(__m128i* temp1,__m128i * temp3) {
    __m128i temp2,temp4;
    temp4 =_mm_aeskeygenassist_si128 (*temp1, 0x0);
    temp2 =_mm_shuffle_epi32(temp4, 0xaa);
    temp4 =_mm_slli_si128 (*temp3, 0x4);
    *temp3 =_mm_xor_si128 (*temp3, temp4);
    temp4 =_mm_slli_si128 (temp4, 0x4);
    *temp3 =_mm_xor_si128 (*temp3, temp4);
    temp4 =_mm_slli_si128 (temp4, 0x4);
    *temp3 =_mm_xor_si128 (*temp3, temp4);
    *temp3 =_mm_xor_si128 (*temp3, temp2);
}


/*
 * Key expansion, 128-bit case
 */
static void aesni_setkey_enc_128( unsigned char *rk,
                                  const unsigned char *key )
{
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i*)rk;
    temp1 = _mm_loadu_si128((__m128i*)key);
    Key_Schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

/*
 * Key expansion, 192-bit case
 */
static void aesni_setkey_enc_192( unsigned char *rk,
                                  const unsigned char *key )
{
    __m128i temp1, temp2, temp3;
    __m128i *Key_Schedule = (__m128i*)rk;
    temp1 = _mm_loadu_si128((__m128i*)key);
    temp3 = _mm_loadu_si128((__m128i*)(key+16));
    Key_Schedule[0]=temp1;
    Key_Schedule[1]=temp3;
    temp2=_mm_aeskeygenassist_si128 (temp3,0x1);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[1] = (__m128i) _mm_shuffle_pd((__m128d)Key_Schedule[1], (__m128d)temp1,0);
    Key_Schedule[2] = (__m128i) _mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    temp2 =_mm_aeskeygenassist_si128(temp3,0x2);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[3]=temp1;
    Key_Schedule[4]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x4);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[4] = (__m128i) _mm_shuffle_pd((__m128d)Key_Schedule[4], (__m128d)temp1,0);
    Key_Schedule[5] = (__m128i) _mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x8);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[6]=temp1;
    Key_Schedule[7]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x10);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[7] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[7], (__m128d)temp1,0);
    Key_Schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x20);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[9]=temp1;
    Key_Schedule[10]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x40);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[10] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[10], (__m128d)temp1,0);
    Key_Schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x80);
    KEY_192_ASSIST(&temp1, &temp2, &temp3);
    Key_Schedule[12]=temp1;
}

/*
 * Key expansion, 256-bit case
 */
static void aesni_setkey_enc_256( unsigned char *rk,
                                  const unsigned char *key ) {
    __m128i temp1, temp2, temp3;
    __m128i *Key_Schedule = (__m128i*)rk;
    temp1 =_mm_loadu_si128((__m128i*)key);
    temp3 =_mm_loadu_si128((__m128i*)(key+16));
    Key_Schedule[0] = temp1;
    Key_Schedule[1] = temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x01);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[2]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[3]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x02);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[4]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[5]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x04);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[6]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[7]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x08);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[8]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[9]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x10);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[10]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[11]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x20);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[12]=temp1;
    KEY_256_ASSIST_2(&temp1, &temp3);
    Key_Schedule[13]=temp3;
    temp2 =_mm_aeskeygenassist_si128 (temp3,0x40);
    KEY_256_ASSIST_1(&temp1, &temp2);
    Key_Schedule[14]=temp1;
}

/*
 * Key expansion, wrapper
 */
int mbedtls_aesni_setkey_enc( unsigned char *rk,
                      const unsigned char *key,
                      size_t bits )
{
    switch( bits )
    {
        case 128: aesni_setkey_enc_128( rk, key ); break;
        case 192: aesni_setkey_enc_192( rk, key ); break;
        case 256: aesni_setkey_enc_256( rk, key ); break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    return( 0 );
}

#endif /* MBEDTLS_HAVE_X86_64 */

#endif /* MBEDTLS_AESNI_C */





