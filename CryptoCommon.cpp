#include <fstream>
#include "CryptoCommon.h"
#define EXPORTED_CIPHERTEXT_SIZE_BYTES PAILLIER_BITS_TO_BYTES(KEY_LENGTH)
using namespace std;
using namespace CryptoPP;

string ciphertext_base64(paillier_ciphertext_t* ciphertext){
	// Export the ciphertext to bytes.
	size_t ct_as_bytes_length;
	byte* ct_as_bytes = (byte*)mpz_export(NULL, &ct_as_bytes_length, 1, 1, 1, 0, ciphertext->c);
	// Convert the bytes to base 64.
	string encoded;
	StringSource ss(ct_as_bytes, EXPORTED_CIPHERTEXT_SIZE_BYTES, true, new Base64Encoder(new StringSink(encoded), true, 100));
	// Clean up.
	free(ct_as_bytes);
	return encoded;
}

void ciphertext_sha256(mpz_t& rop, paillier_ciphertext_t* ciphertext){
	// Export the ciphertext to bytes.
	size_t ct_as_bytes_length;
	byte* ct_as_bytes = (byte*)mpz_export(NULL, &ct_as_bytes_length, 1, 1, 1, 0, ciphertext->c);
	// Calculate the SHA-256 digest.
	byte digest[SHA256::DIGESTSIZE];
	SHA256().CalculateDigest(digest, ct_as_bytes, ct_as_bytes_length);
	// Put the digest into an GMP integer.
	mpz_init(rop);
	mpz_import(rop, SHA256::DIGESTSIZE, 1, 1, 1, 0, digest);
	// Clean up.
	free(ct_as_bytes);
}

bool read_pubkey_from_file(int& numCandidates, int& numVotersPlusOne, paillier_pubkey_t** pub){
	ifstream ifspub(KEY_FILE_PUBLIC);
	if(!ifspub){
		return false;
	}
	char pubHex[KEY_LENGTH_HEX + 1];
	ifspub.getline(pubHex, KEY_LENGTH_HEX + 1);
	ifspub >> numCandidates;
	ifspub >> numVotersPlusOne;
	ifspub.close();
	if(numCandidates < 2 || numVotersPlusOne < 2){
		return false;
	}
	*pub = paillier_pubkey_from_hex(pubHex);
	return true;
}
