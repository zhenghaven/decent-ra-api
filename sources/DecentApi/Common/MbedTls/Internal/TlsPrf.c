/*
 *  SSLv3/TLSv1 shared functions
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
 *  The SSL 3.0 specification was drafted by Netscape in 1996,
 *  and became an IETF standard in 1999.
 *
 *  http://wp.netscape.com/eng/ssl3/
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */

#include <string.h>

#include <mbedtls/ssl.h>
#include <mbedtls/md.h>

//function extracted from mbedTLS. Function name is changed to
// avoid conflicts
//This duplication will be removed once the newer version of
// mbedTLS, which provides TLS PRF functions, is available
int mbedtlscpp_tls_prf_generic( mbedtls_md_type_t md_type,
							const unsigned char *secret, size_t slen,
							const char *label,
							const unsigned char *random, size_t rlen,
							unsigned char *dstbuf, size_t dlen )
{
	size_t nb;
	size_t i, j, k, md_len;
	unsigned char tmp[128];
	unsigned char h_i[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md_info;
	mbedtls_md_context_t md_ctx;
	int ret;

	mbedtls_md_init( &md_ctx );

	if( ( md_info = mbedtls_md_info_from_type( md_type ) ) == NULL )
		return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

	md_len = mbedtls_md_get_size( md_info );

	if( sizeof( tmp ) < md_len + strlen( label ) + rlen )
		return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

	nb = strlen( label );
	memcpy( tmp + md_len, label, nb );
	memcpy( tmp + md_len + nb, random, rlen );
	nb += rlen;

	/*
	 * Compute P_<hash>(secret, label + random)[0..dlen]
	 */
	if ( ( ret = mbedtls_md_setup( &md_ctx, md_info, 1 ) ) != 0 )
		return( ret );

	mbedtls_md_hmac_starts( &md_ctx, secret, slen );
	mbedtls_md_hmac_update( &md_ctx, tmp + md_len, nb );
	mbedtls_md_hmac_finish( &md_ctx, tmp );

	for( i = 0; i < dlen; i += md_len )
	{
		mbedtls_md_hmac_reset ( &md_ctx );
		mbedtls_md_hmac_update( &md_ctx, tmp, md_len + nb );
		mbedtls_md_hmac_finish( &md_ctx, h_i );

		mbedtls_md_hmac_reset ( &md_ctx );
		mbedtls_md_hmac_update( &md_ctx, tmp, md_len );
		mbedtls_md_hmac_finish( &md_ctx, tmp );

		k = ( i + md_len > dlen ) ? dlen % md_len : md_len;

		for( j = 0; j < k; j++ )
			dstbuf[i + j]  = h_i[j];
	}

	mbedtls_md_free( &md_ctx );

	mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
	mbedtls_platform_zeroize( h_i, sizeof( h_i ) );

	return( 0 );
}
