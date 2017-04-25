CC=g++
CFLAGS=-Wall -Werror -g -fvar-tracking -std=c++11 -lpaillier -lgmp -lcryptopp
PARTS=\
	CryptoCommon\

all: cast-vote admin-keygen admin-tokens

%.o: %.cpp $(foreach part, $(PARTS), $(part).h) paillier.h
	$(CC) $< -c -o $@ $(CFLAGS)

cast-vote admin-keygen admin-tokens: %: $(foreach part, $(PARTS), $(part).o) %.o
	$(CC) $(foreach part, $(PARTS), $(part).o) $@.o -o $@ $(CFLAGS)

tests: paillier.h tests.cpp
	$(CC) tests.cpp -o tests $(CFLAGS)

clean:
	rm $(foreach part, $(PARTS), $(part).o) tests\
		cast-vote admin-keygen admin-tokens\
		cast-vote.o admin-keygen.o admin-tokens.o;\
		true
