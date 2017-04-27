#include <string>
#include <gmp.h>
#include "paillier.h"
#define KEY_LENGTH 2048
#define KEY_LENGTH_HEX KEY_LENGTH / 4
#define TOKEN_LENGTH KEY_LENGTH - 256
#define KEY_FILE_PUBLIC "public-key.txt"
#define KEY_FILE_PRIVATE "private-key.txt"
#define TOKEN_FILE "tokens.txt"

// Converts a ciphertext into a base 64 string or vice versa.
std::string ciphertext_base64(paillier_ciphertext_t* ciphertext);
paillier_ciphertext_t* base64_ciphertext(const std::string& encoded);

// Sets rop to a GMP integer of the SHA-256 digest of a ciphertext.
void ciphertext_sha256(mpz_t& rop, paillier_ciphertext_t* ciphertext);

// Removes hyphens from a voter token from stdin.
// Returns false if non-numeric characters other than hyphens are found.
bool sanitize_voter_token(std::string& str_voter_token);

// Reads the public key as well as the numbers of voters and candidates from a file.
bool read_pubkey_from_file(int& numCandidates, int& numVotersPlusOne, paillier_pubkey_t** pub);
bool read_pubkey_from_file(int& numCandidates, int& numVotersPlusOne, paillier_pubkey_t** pub, std::string& electionName, std::string& electionEmailAddress);

// Reads the private key from a file. Pass in pub, and prv will be set.
bool read_prvkey_from_file(paillier_pubkey_t* pub, paillier_prvkey_t** prv);
