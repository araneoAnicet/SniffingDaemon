#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>

#define DEFAULT_BUFFER_SIZE 65536

struct SnifferSocket {
    int fd;
    unsigned char* buffer;
    int buffer_size;
    int domain;
    int type;
    int protocol;
};

typedef struct SnifferSocket SnifferSocket;

struct Sniffer {
    SnifferSocket socket;

};

typedef struct Sniffer Sniffer;


int create_sniffer_socket(Sniffer* sniffer);
void close_sniffer_socket(Sniffer* sniffer);
void print_headers(struct ethhdr* eth);
int sniff(Sniffer* sniffer);
