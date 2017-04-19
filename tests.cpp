#include <cstdlib>
#include <ctime>
#include <iostream>
#include <gmp.h>       // Install libgmp first and compile with -lgmp
#include "paillier.h"  // Install libpaillier first and compile with -lpaillier
#define KEY_LENGTH 2048
using namespace std;

int main(){
	// Test the keygen function by generating a public and private key pair.
	cout << "Generating Paillier key pair with " << KEY_LENGTH << " bits..." << endl;
	// The following two declarations are pointers to pointers of structs.
	paillier_pubkey_t* pub;
	paillier_prvkey_t* prv;
	// Run the keygen function.
	paillier_keygen(KEY_LENGTH, &pub, &prv, paillier_get_rand_devurandom);
	// Print out the keys.
	cout << "Public key:       n=";
	mpz_out_str(stdout, 10, pub->n);
	cout << "\nPrivate key: lambda=";
	mpz_out_str(stdout, 10, prv->lambda);
	cout << endl;
	// Check that decryption is the inverse of encryption.
	cout << "\nTesting encryption and decryption...\n";
	// Seed the random number generator.
	srand(time(NULL));
	// Make a random message.
	unsigned long int m = rand();
	cout << "m=" << m;
	paillier_plaintext_t* plaintext = paillier_plaintext_from_ui(m);
	// Encrypt it and then decrypt it.
	paillier_ciphertext_t* ciphertext = paillier_enc(NULL, pub, plaintext, paillier_get_rand_devurandom);
	paillier_dec(plaintext, pub, prv, ciphertext);
	// Show the decrypted plaintext.
	cout << ", m'=";
	mpz_out_str(stdout, 10, plaintext->m);
	cout << endl;
	// Clean up.
	free(pub);
	free(prv);
	free(ciphertext);
	free(plaintext);
	return 0;
}
