#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <unordered_set>
#include "CryptoCommon.h"
#define KEY_LENGTH_BYTES PAILLIER_BITS_TO_BYTES(KEY_LENGTH)
#define TOKEN_SEPARATE_NUM_DIGITS 5
#define MAX_COLLISIONS 15
using namespace std;

void init_rand(gmp_randstate_t& rand){
	gmp_randinit_default(rand);
	// Get bytes from /dev/urandom.
	void* buf = malloc(KEY_LENGTH_BYTES);
	paillier_get_rand_devrandom(buf, KEY_LENGTH_BYTES);
	// Import those bytes into a GMP integer.
	mpz_t s;
	mpz_init(s);
	mpz_import(s, KEY_LENGTH_BYTES, 0, 1, 0, 0, buf);
	// Seed the random number generator.
	gmp_randseed(rand, s);
	// Clean up.
	mpz_clear(s);
	free(buf);
}

int main(){
	cout << "This program generates voter ID codes." << endl;
	// Read the public key from a file.
	string electionName, electionEmailAddress;
	int numCandidates, numVotersPlusOne;
	paillier_pubkey_t* pub;
	if(!read_pubkey_from_file(numCandidates, numVotersPlusOne, &pub, electionName, electionEmailAddress)){
		cerr << "The public key file is missing or corrupt.\n";
		return 1;
	}
	cout << "Generating tokens for election: " << electionName << '\n';
	// Initialize the random state for GMP.
	unsigned int numTokensDesired = numVotersPlusOne - 1;
	gmp_randstate_t rand;
	init_rand(rand);
	// Open token file for writing.
	ofstream ofs(TOKEN_FILE);
	if(!ofs){
		cerr << "Unable to open " << TOKEN_FILE << " for writing.\n";
		return 2;
	}
	// Generate tokens.
	cout << "Generating " << numTokensDesired << " tokens...";
	cout.flush();
	unordered_set<string> generated;
	unsigned int num_collisions = 0;
	while(generated.size() < numTokensDesired){
		// Create a GMP integer.
		mpz_t token;
		mpz_init(token);
		// Get a random value between 0 and pub->n - 1, inclusive.
		mpz_urandomm(token, rand, pub->n);
		// Discard the lower 256 bits of the token. Those 256 bits will be used instead for a SHA-256 hash.
		mpz_tdiv_q_2exp(token, token, 256);
		// Allocate a buffer to hold a base 10 string representation of the token.
		char* buf = (char*)malloc(mpz_sizeinbase(token, 10) + 2);
		// Get the value as a string in base 10.
		mpz_get_str(buf, 10, token);
		// Add it to the set of generated tokens.
		auto old_size = generated.size();
		generated.emplace(buf);
		if(old_size == generated.size()){
			if(++num_collisions > MAX_COLLISIONS){
				cerr << MAX_COLLISIONS << " tokens have recurred randomly. You requested too many tokens.\n";
				return 3;
			}
		}
		// Clean up.
		free(buf);
		mpz_clear(token);
	}
	cout << " done. Avoided " << num_collisions << " collision(s).\n";
	// Write the tokens to a file.
	cout << "Writing tokens to a file...";
	cout.flush();
	for(const string& token : generated){
		unsigned int group_start = (token.length() - 1) % TOKEN_SEPARATE_NUM_DIGITS + 1;
		// Print out the first block of numbers.
		ofs << token.substr(0, group_start);
		// Print the other blocks separated with hyphens.
		for(; group_start < token.length(); group_start += TOKEN_SEPARATE_NUM_DIGITS){
			ofs << '-' << token.substr(group_start, TOKEN_SEPARATE_NUM_DIGITS);
		}
		ofs << endl;
	}
	cout << " done." << endl;
	// Clean up.
	paillier_freepubkey(pub);
	gmp_randclear(rand);
	return 0;
}
