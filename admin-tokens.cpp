#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include "CryptoCommon.h"
#define TOKEN_SEPARATE_NUM_DIGITS 5
using namespace std;

int main(){
	cerr << "This program generates voter ID codes.\n";
	cerr << "The codes will be written to stdout.\n";
	// Initialize the random state for GMP.
	int numTokensDesired;
	gmp_randstate_t rand;
	gmp_randinit_default(rand);
	// Generate tokens.
	cerr << "How many do you want to generate? ";
	cin >> numTokensDesired;
	cerr << '\n';
	for(int i = 0; i < numTokensDesired; ++i){
		// Create a GMP integer.
		mpz_t token;
		mpz_init(token);
		// Get a random value.
		mpz_urandomb(token, rand, TOKEN_LENGTH);
		char* buf = (char*)malloc(mpz_sizeinbase(token, 10) + 2);
		// Get the value as a string in base 10.
		mpz_get_str(buf, 10, token);
		int length_of_string = strlen(buf),
			group_start = (length_of_string - 1) % TOKEN_SEPARATE_NUM_DIGITS + 1;
		// Print out the first block of numbers.
		cout.write(buf, group_start);
		// Print the other blocks separated with hyphens.
		for(; group_start < length_of_string; group_start += TOKEN_SEPARATE_NUM_DIGITS){
			cout << '-';
			cout.write(buf + group_start, TOKEN_SEPARATE_NUM_DIGITS);
		}
		cout << endl;
		// Clean up.
		mpz_clear(token);
		free(buf);
	}
	return 0;
}