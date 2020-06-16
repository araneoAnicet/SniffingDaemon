all: test

test: test.o Sniffer/Sniffer.o
	clang test.o Sniffer/Sniffer.o -o test

test.o: test.c
	clang -c test.c

Sniffer.o: Sniffer/Sniffer.c
	clang -c Sniffer/Sniffer.c

clean:
	rm -rf *.o test

