CC=g++
CFLAGS=-Wall -Werror -std=c++11 -lpaillier -lgmp

tests: paillier.h tests.cpp
	$(CC) tests.cpp -o tests $(CFLAGS)
clean:
	rm tests
