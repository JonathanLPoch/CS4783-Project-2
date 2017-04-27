#include <fstream>
#include <iostream>
#include <map>
#include <stack>
#include <string>
#include <unordered_set>
#include "CryptoCommon.h"
using namespace std;
#define STRING_STARTSWITH(the_str, starts_with) (the_str.compare(0, starts_with.length(), starts_with) == 0)
const string BEGIN("BEGIN:");
const string END("END:");

// Converts a GMP integer into a string of bytes.
// The string return type is just a convenient container.
string mpz_to_bytes(const mpz_t& token){
	size_t token_as_bytes_length;
	char* buf = (char*)mpz_export(NULL, &token_as_bytes_length, 0, 1, 0, 0, token);
	string result(buf, token_as_bytes_length);
	free(buf);
	return result;
}

// Reads TOKEN_FILE and adds the tokens in the file to the unordered_set.
bool read_tokens_file(unordered_set<string>& tokens){
	ifstream tokens_file(TOKEN_FILE);
	if(!tokens_file){
		return false;
	}
	// This unordered_set will contain the tokens as exported by mpz_export.
	string line;
	size_t line_num = 0;
	while(getline(tokens_file, line)){
		++line_num;
		// Remove the hyphens from the string.
		if(sanitize_voter_token(line)){
			// Convert the base 10 string into a GMP integer.
			mpz_t token;
			if(mpz_init_set_str(token, line.c_str(), 10) == 0){
				tokens.insert(mpz_to_bytes(token));
			}else{
				cerr << "Token error: line " << line_num << ": value cannot be parsed as base 10\n";
			}
			mpz_clear(token);
		}else{
			cerr << "Token error: line " << line_num << ": value is not numeric\n";
		}
	}
	return true;
}

int main(){
	// Read the public key from a file.
	int numCandidates, numVotersPlusOne;
	paillier_pubkey_t* pub;
	if(!read_pubkey_from_file(numCandidates, numVotersPlusOne, &pub)){
		cerr << "The public key file is missing or corrupt.\n";
		return 1;
	}
	// Read the private key from a file.
	paillier_prvkey_t* prv;
	if(!read_prvkey_from_file(pub, &prv)){
		cerr << "The private key file is missing.\n";
		return 2;
	}
	// Read the tokens from a file.
	unordered_set<string> tokens, tokens_used;
	if(!read_tokens_file(tokens)){
		cerr << "The file containing tokens is missing.\n";
		return 3;
	}
	// Get 2^256.
	mpz_t z2to256;
	mpz_init_set_ui(z2to256, 1);
	mpz_mul_2exp(z2to256, z2to256, 256);
	// This variable will accumulate the election results.
	// The Paillier cryptosystem has additive homomorphism. A product of two ciphertexts is equal to the ciphertext of the sum of the two plaintexts.
	// Every ballot will be multiplied with this variable.
	paillier_ciphertext_t* product = paillier_create_enc_zero();
	// Start tallying votes from standard input.
	cerr << "Reading votes from stdin...\n";
	stack<string> began_sections;
	string line, current_value, current_ballot, current_mac;
	size_t line_num = 0;
	size_t envelope_num = 0;
	while(getline(cin, line)){
		++line_num;
		if(STRING_STARTSWITH(line, BEGIN)){
			// This is the beginning of a section.
			began_sections.push(line.substr(BEGIN.length()));
			current_value = "";
		}else if(STRING_STARTSWITH(line, END)){
			// This is the end of a section.
			// Make sure that at least one section is open.
			if(began_sections.empty()){
				cerr << "Error: line " << line_num << ": no corresponding begin tag\n";
			}else{
				// Make sure that it matches the section that was last began.
				string tag = line.substr(END.length());
				if(tag == began_sections.top()){
					// This END tag matches the last BEGIN tag, so process the data.
					began_sections.pop();
					if(tag == "ENVELOPE"){
						// This is the end of an envelope.
						// Make sure that current_ballot and current_mac are set.
						if(current_ballot.length() && current_mac.length()){
							++envelope_num;
							// Both the ballot and the message authentication code should be in base 64 strings.
							// Convert them back to Pailier ciphertexts now.
							paillier_ciphertext_t* ctVote = base64_ciphertext(current_ballot);
							paillier_ciphertext_t* ctAuthentic = base64_ciphertext(current_mac);
							// Decrypt the message authentication code.
							paillier_plaintext_t* ptAuthentic = paillier_dec(NULL, pub, prv, ctAuthentic);
							paillier_freeciphertext(ctAuthentic);
							// Get the lower 256 bits of this plaintext; it should be a SHA-256 sum.
							mpz_t zHashFromVoter;
							mpz_init(zHashFromVoter);
							mpz_mod(zHashFromVoter, ptAuthentic->m, z2to256);
							// Recalculate the SHA-256 sum of the encrypted ballot.
							mpz_t zHashRedone;
							ciphertext_sha256(zHashRedone, ctVote);
							// Make sure that the hashes match.
							if(mpz_cmp(zHashFromVoter, zHashRedone) == 0){
								// The hashes match. Get the voter's token.
								mpz_t zTokenFromVoter;
								mpz_init(zTokenFromVoter);
								mpz_tdiv_q_2exp(zTokenFromVoter, ptAuthentic->m, 256);
								// Check that the token is in the set of valid tokens.
								string bTokenFromVoter = mpz_to_bytes(zTokenFromVoter);
								if(tokens.find(bTokenFromVoter) != tokens.end()){
									// Check that the token has not been used already.
									if(tokens_used.find(bTokenFromVoter) == tokens_used.end()){
										// Mark this token as used.
										tokens_used.insert(bTokenFromVoter);
										// This ballot has been validated and should be accepted. It will now be counted in the election results.
										paillier_mul(pub, product, product, ctVote);
									}else{
										cerr << "Breach: line " << line_num << " or envelope " << envelope_num << ": this token has already been used\n";
									}
								}else{
									cerr << "Breach: line " << line_num << " or envelope " << envelope_num << ": the token is not in the set of valid tokens\n";
								}
								// Clean up.
								mpz_clear(zTokenFromVoter);
							}else{
								cerr << "Breach: line " << line_num << " or envelope " << envelope_num << ": the checksum is incorrect\n";
								cerr <<   " >   Supplied: ";
								mpz_out_str(stderr, 16, zHashFromVoter);
								cerr << "\n > Calculated: ";
								mpz_out_str(stderr, 16, zHashRedone);
								cerr << '\n';
							}
							// Clean up.
							paillier_freeciphertext(ctVote);
							paillier_freeplaintext(ptAuthentic);
							mpz_clear(zHashFromVoter);
							mpz_clear(zHashRedone);
						}else{
							cerr << "Error: line " << line_num << ": envelope is missing ballot and/or MAC\n";
						}
					}else if(tag == "BALLOT"){
						// Store the ballot in a string.
						current_ballot = move(current_value);
						current_value = "";
					}else if(tag == "MAC"){
						// Store the message authentication code in a string.
						current_mac = move(current_value);
						current_value = "";
					}else{
						cerr << "Error: line " << line_num << ": unknown tag " << tag << '\n';
					}
				}else{
					cerr << "Error: line " << line_num << ": end tag does not match begin tag\n";
				}
			}
		}else{
			current_value += line;
		}
	}
	mpz_clear(z2to256);
	cout << endl;
	// We have reached the end of the input.
	// Decrypt the product of the ciphertexts. This is equal to the sum of the plaintexts.
	paillier_plaintext_t* sum = paillier_dec(NULL, pub, prv, product);
	// Print out the election results.
	cout << "Here are the election results:\n";
	for(int c = 0; c < numCandidates; ++c){
		cout << "Candidate " << (c + 1) << ": ";
		// Ultimately, we want floor(({product} mod (({number of voters}+1)^(c+1)))/(({number of voters}+1)^c)).
		// Let's start with ({number of voters}+1)^(c+1).
		mpz_t next_place_value;
		mpz_init(next_place_value);
		mpz_ui_pow_ui(next_place_value, numVotersPlusOne, c + 1);
		// We're left with floor(({product} mod next_place_value)/(({number of voters}+1)^c)).
		// Let's get ({number of voters}+1)^c.
		// TODO: we can cache next_place_value from the last iteration and use it here
		mpz_t this_place_value;
		mpz_init(this_place_value);
		mpz_ui_pow_ui(this_place_value, numVotersPlusOne, c);
		// We're left with floor(({product} mod next_place_value)/this_place_value).
		// Let's get {product} mod next_place_value.
		mpz_t x;
		mpz_init(x);
		mpz_mod(x, sum->m, next_place_value);
		// We're left with floor(x/this_place_value).
		// Let's get it.
		mpz_fdiv_q(x, x, this_place_value);
		// Print the result.
		mpz_out_str(stdout, 10, x);
		cout << " vote(s)\n";
		// Clean up.
		mpz_clear(next_place_value);
		mpz_clear(this_place_value);
		mpz_clear(x);
	}
	cout << endl;
	paillier_freeciphertext(product);
	paillier_freeplaintext(sum);
	return 0;
}
