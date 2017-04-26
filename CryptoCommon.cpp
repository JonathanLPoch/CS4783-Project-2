#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include "CryptoCommon.h"
using namespace std;
using namespace CryptoPP;

string ciphertext_base64(paillier_ciphertext_t* ciphertext){
	// Export the ciphertext to bytes.
	size_t ct_as_bytes_length;
	byte* ct_as_bytes = (byte*)mpz_export(NULL, &ct_as_bytes_length, 1, 1, 1, 0, ciphertext->c);
	// Convert the bytes to base 64.
	string encoded;
	StringSource ss(ct_as_bytes, ct_as_bytes_length, true, new Base64Encoder(new StringSink(encoded), true, 100));
	// Clean up.
	free(ct_as_bytes);
	return encoded;
}

paillier_ciphertext_t* base64_ciphertext(const string& encoded){
	string decoded;
	// Convert the base 64 string to a string of bytes.
	StringSource ss(encoded, true, new Base64Decoder(new StringSink(decoded)));
	// Import these bytes into a new ciphertext.
	paillier_ciphertext_t* ciphertext = paillier_create_enc_zero();
	mpz_import(ciphertext->c, decoded.length(), 1, 1, 1, 0, decoded.c_str());
	return ciphertext;
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

bool sanitize_voter_token(string& str_voter_token){
	// Allocate a character array.
	char* temp = (char*) malloc(str_voter_token.size() + 1);
	size_t i = 0;
	// Copy numeric characters to the character array.
	for(char c : str_voter_token){
		if('0' <= c && c <= '9'){
			// This is a numeric character.
			temp[i++] = c;
		}else if(c != '-'){
			// This is not a numeric character, and it is not a hyphen.
			free(temp);
			return false;
		}
	}
	// Terminate the character array.
	temp[i] = 0;
	// Set the original string to the string version of this character array.
	str_voter_token = temp;
	// Clean up.
	free(temp);
	return true;
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

bool read_prvkey_from_file(paillier_pubkey_t* pub, paillier_prvkey_t** prv){
	ifstream ifsprv(KEY_FILE_PRIVATE);
	if(!ifsprv){
		return false;
	}
	char prvHex[KEY_LENGTH_HEX + 1];
	ifsprv.getline(prvHex, KEY_LENGTH_HEX + 1);
	ifsprv.close();
	*prv = paillier_prvkey_from_hex(prvHex, pub);
	return true;
}
