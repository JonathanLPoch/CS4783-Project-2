#include <fstream>
#include <iostream>
#include "CryptoCommon.h"
using namespace std;

bool public_key_big_enough(int numVoters, int numCandidates, paillier_pubkey_t* pub){
	mpz_t v_to_c;
	mpz_init(v_to_c);
	// Find {number of voters + 1}^{number of candidates} - 1, which is the
	// sum of all ballots when all voters vote for all candidates.
	mpz_ui_pow_ui(v_to_c, numVoters + 1, numCandidates);
	mpz_sub_ui(v_to_c, v_to_c, 1);
	// Check that that value is less than the public key.
	bool result = mpz_cmp(v_to_c, pub->n) < 0;
	// Clean up.
	mpz_clear(v_to_c);
	return result;
}

int main(){
	int numCandidates, numVoters;
	cout << "This program will set up the election." << endl;
	cout << "At most, how many candidates will there be? ";
	cout.flush();
	cin >> numCandidates;
	cout << "At most, how many voters will there be? ";
	cout.flush();
	cin >> numVoters;
	if(numCandidates < 2 || numVoters < 2){
		cerr << "There must be at least two candidates and at least two voters.\n";
		return 1;
	}
	// Generate a Paillier public/private key pair.
	cout << "Generating Paillier key pair with " << KEY_LENGTH << " bits..." << endl;
	paillier_pubkey_t* pub;
	paillier_prvkey_t* prv;
	paillier_keygen(KEY_LENGTH, &pub, &prv, paillier_get_rand_devurandom);
	if(!public_key_big_enough(numVoters, numCandidates, pub)){
		cerr << "There are too many voters and candidates for a public key of this length.\n";
		return 2;
	}
	// Save the public key along with the numbers of candidates and voters to a file.
	ofstream ofspub(KEY_FILE_PUBLIC);
	if(ofspub){
		ofspub << paillier_pubkey_to_hex(pub) << endl;
		ofspub << numCandidates << '\n' << (numVoters + 1) << endl;
		ofspub.close();
	}else{
		cerr << "Warning: could not write file for public key.\n";
	}
	// Save the private key to a file.
	ofstream ofsprv(KEY_FILE_PRIVATE);
	if(ofsprv){
		ofsprv << paillier_prvkey_to_hex(prv) << endl;
		ofsprv.close();
	}else{
		cerr << "Warning: could not write file for private key.\n";
	}
	// Clean up.
	paillier_freepubkey(pub);
	paillier_freeprvkey(prv);
	cout << "This process has completed." << endl;
	return 0;
}
