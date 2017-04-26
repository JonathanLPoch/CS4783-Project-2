#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <gmp.h>
#include "paillier.h"
#define KEY_LENGTH 2048
#define KEY_LENGTH_HEX KEY_LENGTH / 4
#define TOKEN_LENGTH KEY_LENGTH - 256
#define KEY_FILE_PUBLIC "public-key.txt"
#define KEY_FILE_PRIVATE "private-key.txt"
#define TOKEN_FILE "tokens.txt"

// Converts a ciphertext into a base 64 string.
std::string ciphertext_base64(paillier_ciphertext_t* ciphertext);

// Sets rop to a GMP integer of the SHA-256 digest of a ciphertext.
void ciphertext_sha256(mpz_t& rop, paillier_ciphertext_t* ciphertext);

// Reads the public key as well as the numbers of voters and candidates from a file.
bool read_pubkey_from_file(int& numCandidates, int& numVotersPlusOne, paillier_pubkey_t** pub);
