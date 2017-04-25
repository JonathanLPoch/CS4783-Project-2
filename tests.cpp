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
	// Encrypt twice and then decrypt twice. Note: this doesn't seem to work.
	paillier_plaintext_t* double_test_m = new paillier_plaintext_t();
	mpz_init_set(double_test_m->m, ciphertext->c);
	paillier_ciphertext_t* double_test_c = paillier_enc(NULL, pub, double_test_m, paillier_get_rand_devurandom);
	paillier_dec(double_test_m, pub, prv, double_test_c);
	mpz_set(double_test_c->c, double_test_m->m);
	paillier_dec(double_test_m, pub, prv, double_test_c);
	// Show the decrypted plaintext.
	cout << ", m'=D(E(m))=";
	mpz_out_str(stdout, 10, plaintext->m);
	cout << ", D(D(E(E(m))))=";
	mpz_out_str(stdout, 10, double_test_m->m);
	mpz_clear(double_test_m->m);
	delete double_test_m;
	paillier_freeciphertext(double_test_c);
	cout << endl;
	// Make another random message.
	unsigned long int m2 = rand();
	cout << "m_2=" << m2;
	paillier_plaintext_t* plaintext2 = paillier_plaintext_from_ui(m2);
	// Encrypt it multiply it with the first plaintext. This will test homomorphic addition.
	paillier_ciphertext_t* ciphertext2 = paillier_enc(NULL, pub, plaintext2, paillier_get_rand_devurandom);
	paillier_ciphertext_t* product = new paillier_ciphertext_t();
	mpz_init(product->c);
	paillier_mul(pub, product, ciphertext, ciphertext2);
	paillier_freeciphertext(ciphertext);
	paillier_freeciphertext(ciphertext2);
	// Add the plaintexts without any crypto. This is plain old addition.
	mpz_t sum_plain;
	mpz_init(sum_plain);
	mpz_add(sum_plain, plaintext->m, plaintext2->m);
	mpz_mod(sum_plain, sum_plain, pub->n);
	cout << ", (m'+m_2) mod n=";
	mpz_out_str(stdout, 10, sum_plain);
	paillier_freeplaintext(plaintext);
	paillier_freeplaintext(plaintext2);
	// Decrypt the product of the ciphertexts to get the sum of the plaintexts.
	paillier_plaintext_t* sum = paillier_dec(NULL, pub, prv, product);
	cout << ", D(E(m')*E(m_2) mod n^2)=";
	mpz_out_str(stdout, 10, sum->m);
	cout << endl;
	// Done.
	paillier_freepubkey(pub);
	paillier_freeprvkey(prv);
	paillier_freeplaintext(sum);
	mpz_clear(product->c);
	delete product;
	return 0;
}
