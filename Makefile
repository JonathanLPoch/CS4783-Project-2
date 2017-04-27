CC=g++
CFLAGS=-Wall -Werror -g -fvar-tracking -std=c++11 -lpaillier -lgmp -lcryptopp

all: cast-vote admin-keygen admin-tokens tally-votes

%.o: %.cpp CryptoCommon.h paillier.h
	$(CC) $< -c -o $@ $(CFLAGS)

admin-keygen admin-tokens tally-votes: %: CryptoCommon.o %.o
	$(CC) CryptoCommon.o $@.o -o $@ $(CFLAGS)

cast-vote: %: CryptoCommon.o %.o
	$(CC) CryptoCommon.o $@.o -o $@ -static $(CFLAGS)

clean:
	rm $(foreach part, $(PARTS), $(part).o)\
		cast-vote admin-keygen admin-tokens tally-votes\
		cast-vote.o admin-keygen.o admin-tokens.o tally-votes.o;\
		true
