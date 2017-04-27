CC=g++
CFLAGS=-Wall -Werror -g -fvar-tracking -std=c++11 -lpaillier -lgmp -lcryptopp
PARTS=\
	CryptoCommon\

all: cast-vote admin-keygen admin-tokens tally-votes

%.o: %.cpp $(foreach part, $(PARTS), $(part).h) paillier.h
	$(CC) $< -c -o $@ $(CFLAGS)

cast-vote admin-keygen admin-tokens tally-votes: %: $(foreach part, $(PARTS), $(part).o) %.o
	$(CC) $(foreach part, $(PARTS), $(part).o) $@.o -o $@ $(CFLAGS)

clean:
	rm $(foreach part, $(PARTS), $(part).o)\
		cast-vote admin-keygen admin-tokens tally-votes\
		cast-vote.o admin-keygen.o admin-tokens.o tally-votes.o;\
		true
