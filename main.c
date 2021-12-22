#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha1.h"



static const unsigned char sha1_test_buf[3][57] =
{
    { "abc" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" },
    { "" }
};

static const size_t sha1_test_buflen[3] =
{
    3, 56, 1000
};

static const unsigned char sha1_test_sum[3][20] =
{
    { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
      0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D },
    { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
      0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 },
    { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
      0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F }
};

/*
 * Checkup routine
 */
int main(void)
{
    int i, j, buflen, ret = 0;
    unsigned char buf[1024];
    unsigned char sha1sum[20];
    mbedtls_sha1_context ctx = {0};

    mbedtls_sha1_init( &ctx );

    /*
     * SHA-1
     */
    for( i = 0; i < 3; i++ )
    {
        printf( "  SHA-1 test #%d: ", i + 1 );

        if( ( ret = mbedtls_sha1_starts_ret( &ctx ) ) != 0 )
            goto fail;

        if( i == 2 )
        {
            memset( buf, 'a', buflen = 1000 );

            for( j = 0; j < 1000; j++ )
            {
                ret = mbedtls_sha1_update_ret( &ctx, buf, buflen );
                if( ret != 0 )
                    goto fail;
            }
        }
        else
        {
            ret = mbedtls_sha1_update_ret( &ctx, sha1_test_buf[i],
                                           sha1_test_buflen[i] );
            if( ret != 0 )
                goto fail;
        }

        if( ( ret = mbedtls_sha1_finish_ret( &ctx, sha1sum ) ) != 0 )
            goto fail;

        if( memcmp( sha1sum, sha1_test_sum[i], 20 ) != 0 )
        {
            ret = 1;
            goto fail;
        }

        printf( "passed\n" );
    }

    printf( "\n" );

    goto exit;

fail:
    printf( "failed\n" );

exit:
    mbedtls_sha1_free( &ctx );

    return( ret );
}
