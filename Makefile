all: test

daemonize: Sniffer/Sniffer.o Sniffer/Logger.o  snifferd.o UI/CommandLineInterface.o
	clang -std=gnu99 Sniffer/Sniffer.o Sniffer/Logger.o  snifferd.o UI/CommandLineInterface.o -o snifferd

test: test.o Sniffer/Sniffer.o Sniffer/Logger.o
	clang -std=gnu99 test.o Sniffer/Sniffer.o Sniffer/Logger.o -o test

test.o: test.c
	clang -c test.c

Sniffer.o: Sniffer/Sniffer.c
	clang -c Sniffer/Sniffer.c

Logger.o: Sniffer/Logger.c
	clang -c Sniffer/Logger.c

CommandLineInterface.o: UI/CommandLineInterface.c
	clang -c UI/CommandLineInterface.c

snifferd.o: snifferd.c
	clang -c snifferd.c

clean:
	rm -rf Sniffer/*.o *.o test

