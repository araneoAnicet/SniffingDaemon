#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>
#include <ifaddrs.h>

#define DEFAULT_BUFFER_SIZE 65536

struct SnifferSocket {
    int fd;
    unsigned char* buffer;
    int buffer_size;
    int domain;
    int type;
    int protocol;
    char* interface_name ;  // define an interface name to sniff the packets from (wlan0 / wlan1, ...)
};

typedef struct SnifferSocket SnifferSocket;

struct Sniffer {
    SnifferSocket socket;

};

typedef struct Sniffer Sniffer;


inline int get_interface_addr_by_name(Sniffer* sniffer, struct sockaddr** interface_addr);
int create_sniffer_socket(Sniffer* sniffer);
void close_sniffer_socket(Sniffer* sniffer);
void print_headers(struct ethhdr* eth);
int sniff(Sniffer* sniffer);
