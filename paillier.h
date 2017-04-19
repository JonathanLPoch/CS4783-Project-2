/*
	This is a version of paillier.h from libpaillier adapted for use with C++.
	You still must install libpaillier first using the instructions in the
	INSTALL file in the libpaillier package.
	
	Re-generate this file by doing the following:
	1. Copy this and the next comment blocks.
	2. In the current directory, run command:
		gcc -fpreprocessed -dD -E /usr/local/include/paillier.h >paillier.h
	3. Paste the comment blocks at the top of the newly-created paillier.h.
	4. Find-and-replace `# ` with `// `.
	5. Enclose the function declarations in an extern "C" block.
*/

/*
	libpaillier - A library implementing the Paillier cryptosystem.
	
	Copyright (C) 2006 SRI International.
	
	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful, but
	WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
	General Public License for more details.
*/

// 56 "/usr/local/include/paillier.h"
typedef struct
{
	int bits;
	mpz_t n;
	mpz_t n_squared;
	mpz_t n_plusone;
} paillier_pubkey_t;
typedef struct
{
	mpz_t lambda;
	mpz_t x;
} paillier_prvkey_t;
typedef struct
{
	mpz_t m;
} paillier_plaintext_t;
typedef struct
{
	mpz_t c;
} paillier_ciphertext_t;
extern "C" {
	// 104 "/usr/local/include/paillier.h"
	typedef void (*paillier_get_rand_t) ( void* buf, int len );
	// 118 "/usr/local/include/paillier.h"
	void paillier_keygen( int modulusbits, paillier_pubkey_t** pub, paillier_prvkey_t** prv, paillier_get_rand_t get_rand );
	paillier_ciphertext_t* paillier_enc( paillier_ciphertext_t* res, paillier_pubkey_t* pub, paillier_plaintext_t* pt, paillier_get_rand_t get_rand );
	paillier_plaintext_t* paillier_dec( paillier_plaintext_t* res, paillier_pubkey_t* pub, paillier_prvkey_t* prv, paillier_ciphertext_t* ct );
	// 153 "/usr/local/include/paillier.h"
	void paillier_mul( paillier_pubkey_t* pub, paillier_ciphertext_t* res, paillier_ciphertext_t* ct0, paillier_ciphertext_t* ct1 );
	void paillier_exp( paillier_pubkey_t* pub, paillier_ciphertext_t* res, paillier_ciphertext_t* ct, paillier_plaintext_t* pt );
	// 177 "/usr/local/include/paillier.h"
	paillier_plaintext_t* paillier_plaintext_from_ui( unsigned long int x );
	paillier_plaintext_t* paillier_plaintext_from_bytes( void* m, int len );
	paillier_plaintext_t* paillier_plaintext_from_str( char* str );
	char* paillier_plaintext_to_str( paillier_plaintext_t* pt );
	void* paillier_plaintext_to_bytes( int len, paillier_plaintext_t* pt );
	// 198 "/usr/local/include/paillier.h"
	paillier_ciphertext_t* paillier_ciphertext_from_bytes( void* c, int len );
	void* paillier_ciphertext_to_bytes( int len, paillier_ciphertext_t* ct );
	// 212 "/usr/local/include/paillier.h"
	char* paillier_pubkey_to_hex( paillier_pubkey_t* pub );
	char* paillier_prvkey_to_hex( paillier_prvkey_t* prv );
	paillier_pubkey_t* paillier_pubkey_from_hex( char* str );
	paillier_prvkey_t* paillier_prvkey_from_hex( char* str, paillier_pubkey_t* pub );
	// 227 "/usr/local/include/paillier.h"
	void paillier_freepubkey( paillier_pubkey_t* pub );
	void paillier_freeprvkey( paillier_prvkey_t* prv );
	void paillier_freeplaintext( paillier_plaintext_t* pt );
	void paillier_freeciphertext( paillier_ciphertext_t* ct );
	// 248 "/usr/local/include/paillier.h"
	void paillier_get_rand_devrandom( void* buf, int len );
	void paillier_get_rand_devurandom( void* buf, int len );
	// 261 "/usr/local/include/paillier.h"
	paillier_ciphertext_t* paillier_create_enc_zero();
}
#define PAILLIER_BITS_TO_BYTES(n) ((n) % 8 ? (n) / 8 + 1 : (n) / 8)
