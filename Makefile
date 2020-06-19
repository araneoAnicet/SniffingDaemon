all: test

test: test.o Sniffer/Sniffer.o Sniffer/Logger.o
	clang -std=gnu99 test.o Sniffer/Sniffer.o Sniffer/Logger.o -o test

test.o: test.c
	clang -c test.c

Sniffer.o: Sniffer/Sniffer.c
	clang -c Sniffer/Sniffer.c

Logger.o: Sniffer/Logger.c
	clang -c Sniffer/Logger.c

clean:
	rm -rf Sniffer/*.o *.o test

