CC=g++
CFLAGS=-Wall -Werror -O3 -std=c++11
CLINK=-lpaillier -lgmp -lcryptopp

all: cast-vote admin-keygen admin-tokens tally-votes

%.o: %.cpp CryptoCommon.h paillier.h
	$(CC) $< -c -o $@ $(CFLAGS)

admin-keygen admin-tokens tally-votes: %: CryptoCommon.o %.o
	$(CC) CryptoCommon.o $@.o -o $@ $(CFLAGS) $(CLINK)

cast-vote: %: CryptoCommon.o %.o
	$(CC) CryptoCommon.o $@.o -o $@ -static $(CFLAGS) $(CLINK)

clean:
	rm $(foreach part, $(PARTS), $(part).o)\
		cast-vote admin-keygen admin-tokens tally-votes\
		cast-vote.o admin-keygen.o admin-tokens.o tally-votes.o;\
		true

election-reset:
	rm private-key.txt public-key.txt tokens.txt email.txt votes-downloaded.txt
