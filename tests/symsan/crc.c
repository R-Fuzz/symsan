// A checksum guard: taint has to survive a bit-serial CRC and come out the
// other side still solvable.
//
// Both the message and the trailing checksum come from the file, so the guard
// is symbolic on both sides.  crcSlow's inner loop branches on the top bit of
// the remainder once per message bit, and every one of those branches is
// reachable, so the trace is dominated by them -- the last condition, the one
// that actually matters, is the equality against the stored checksum.  Getting
// past it means carrying a 128-deep chain of shifts and xors through the AST
// without losing a bit.
//
// MSG_LEN is small on purpose.  The work is linear in the message length (8
// conditions per byte, and an input written for each), so the original 4096
// bytes bought nothing this does not already show and cost a great deal of
// wall clock.
//
// CRC-CCITT rather than the CRC-32 the header defaults to, and that is not
// arbitrary: CRC-32 sets REFLECT_DATA, so each message byte goes through
// reflect(x, 8), which clang's idiom recognizer turns into @llvm.bitreverse.i8
// at -O3.  TaintPass handles llvm.bswap but has no case for llvm.bitreverse,
// so the shadow is dropped and the whole message silently goes concrete --
// the test would still pass, in a fraction of the time, having checked
// nothing but "solve for the checksum field".  CCITT does not reflect, so
// nothing hides the gap here.  (reflect() itself is left in place and only its
// 1 << n -> 1UL << n overflow was fixed; it is dead code under CCITT, and
// wrong for any WIDTH above 32 without the fix.)
//
// Replayed as a set rather than by name: what is being asserted is that some
// generated input satisfies the checksum, not where in the queue it lands.
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: python -c"import sys; sys.stdout.buffer.write(b'A'*18)" > %t.bin
// RUN: clang -O3 -o %t.uninstrumented %s
// RUN: %t.uninstrumented %t.bin | FileCheck --check-prefix=CHECK-ORIG %s
// RUN: env KO_USE_FASTGEN=1 %ko-clang -o %t.fg %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %fgtest %t.fg %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-GEN %s
//
// RUN: rm -rf %t.out
// RUN: mkdir -p %t.out
// RUN: env KO_USE_Z3=1 %ko-clang -o %t.z3 %s
// RUN: env TAINT_OPTIONS="taint_file=%t.bin output_dir=%t.out" %t.z3 %t.bin
// RUN: ls %t.out/* | xargs -n1 %t.uninstrumented | FileCheck --check-prefix=CHECK-GEN %s

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib.h"


// modified from  https://barrgroup.com/code/crc.zip
/**********************************************************************
 *
 * Filename:    crc.c
 *
 * Description: Slow and fast implementations of the CRC standards.
 *
 * Notes:       The parameters for each supported CRC standard are
 *				defined in the header file crc.h.  The implementations
 *				here should stand up to further additions to that list.
 *
 *
 * Copyright (c) 2000 by Michael Barr.  This software is placed into
 * the public domain and may be used for any purpose.  However, this
 * notice must not be changed or removed and no warranty is either
 * expressed or implied by its publication or distribution.
 **********************************************************************/

#define CRC_CCITT
#include "crc.h"

// Bytes of message ahead of the 2-byte checksum; see the note at the top.
#define MSG_LEN 16


/*
 * Derive parameters from the standard-specific parameters in crc.h.
 */
#define WIDTH    (8 * sizeof(crc))
#define TOPBIT   (1L << (WIDTH - 1))

#if (REFLECT_DATA == TRUE)
#undef  REFLECT_DATA
#define REFLECT_DATA(X)			(reflect((X), 8))
#else
#undef  REFLECT_DATA
#define REFLECT_DATA(X)			(X)
#endif

#if (REFLECT_REMAINDER == TRUE)
#undef  REFLECT_REMAINDER
#define REFLECT_REMAINDER(X)	((crc) reflect((X), WIDTH))
#else
#undef  REFLECT_REMAINDER
#define REFLECT_REMAINDER(X)	(X)
#endif


/*********************************************************************
 *
 * Function:    reflect()
 *
 * Description: Reorder the bits of a binary sequence, by reflecting
 *				them about the middle position.
 *
 * Notes:		No checking is done that nBits <= 32.
 *
 * Returns:		The reflection of the original data.
 *
 *********************************************************************/
static unsigned long
reflect(unsigned long data, unsigned char nBits)
{
	unsigned long  reflection = 0x00000000;
	unsigned char  bit;

	/*
	 * Reflect the data about the center bit.
	 */
	for (bit = 0; bit < nBits; ++bit)
	{
		/*
		 * If the LSB bit is set, set the reflection of it.
		 */
		if (data & 0x01)
		{
			reflection |= (1UL << ((nBits - 1) - bit));
		}

		data = (data >> 1);
	}

	return (reflection);

}	/* reflect() */


/*********************************************************************
 *
 * Function:    crcSlow()
 *
 * Description: Compute the CRC of a given message.
 *
 * Notes:
 *
 * Returns:		The CRC of the message.
 *
 *********************************************************************/
crc
crcSlow(unsigned char const message[], int nBytes)
{
    crc            remainder = INITIAL_REMAINDER;
	int            byte;
	unsigned char  bit;


    /*
     * Perform modulo-2 division, a byte at a time.
     */
    for (byte = 0; byte < nBytes; ++byte)
    {
        /*
         * Bring the next byte into the remainder.
         */
        remainder ^= (REFLECT_DATA(message[byte]) << (WIDTH - 8));

        /*
         * Perform modulo-2 division, a bit at a time.
         */
        for (bit = 8; bit > 0; --bit)
        {
            /*
             * Try to divide the current data bit.
             */
            if (remainder & TOPBIT)
            {
                remainder = (remainder << 1) ^ POLYNOMIAL;
            }
            else
            {
                remainder = (remainder << 1);
            }
        }
    }

    /*
     * The final remainder is the CRC result.
     */
    return (REFLECT_REMAINDER(remainder) ^ FINAL_XOR_VALUE);

}   /* crcSlow() */

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [file]\n", argv[0]);
    return -1;
  }

  unsigned char buf[MSG_LEN];
  crc checksum;
  FILE* fp = chk_fopen(argv[1], "rb");
  chk_fread(buf, 1, sizeof(buf), fp);
  chk_fread(&checksum, sizeof(checksum), 1, fp);
  fclose(fp);

  if (crcSlow(buf, sizeof(buf)) == checksum) {
    // CHECK-GEN: Good
    printf("Good\n");
  }
  else {
    // CHECK-ORIG: Bad
    printf("Bad\n");
  }
}
