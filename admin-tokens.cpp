#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <unordered_set>
#include "CryptoCommon.h"
#define TOKEN_SEPARATE_NUM_DIGITS 5
using namespace std;

int main(){
	cout << "This program generates voter ID codes.\n";
	cout << "The codes will be written to stdout." << endl;
	// Initialize the random state for GMP.
	unsigned int numTokensDesired;
	gmp_randstate_t rand;
	gmp_randinit_default(rand);
	// Ask the user how many tokens to generate.
	cout << "How many do you want to generate? ";
	cout.flush();
	cin >> numTokensDesired;
	cout << '\n';
	// Open token file for writing.
	ofstream ofs(TOKEN_FILE);
	if(!ofs){
		cerr << "Unable to open " << TOKEN_FILE << " for writing.\n";
		return 1;
	}
	// Generate tokens.
	cout << "Generating " << numTokensDesired << " tokens..." << endl;
	unordered_set<string> generated;
	while(generated.size() < numTokensDesired){
		// Create a GMP integer.
		mpz_t token;
		mpz_init(token);
		// Get a random value.
		mpz_urandomb(token, rand, TOKEN_LENGTH);
		char* buf = (char*)malloc(mpz_sizeinbase(token, 10) + 2);
		// Get the value as a string in base 10.
		mpz_get_str(buf, 10, token);
		// Add it to the set of generated tokens.
		generated.emplace(buf);
		// Clean up.
		free(buf);
		mpz_clear(token);
	}
	// Write the tokens to a file.
	cout << "Writing tokens to a file..." << endl;
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
	cout << "Done." << endl;
	return 0;
}
