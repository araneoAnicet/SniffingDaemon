#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "Logger.h"
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
    PacketLog* packet_logs;  // an array of packets
    int packet_logs_size;
};

typedef struct Sniffer Sniffer;
static Sniffer* global_sniffer;

pid_t get_daemon_pid();

int check_if_interface_is_available(char* interface_name);
void get_configuration(Sniffer* sniffer);
int create_sniffer_socket(Sniffer* sniffer);
void close_sniffer_socket(Sniffer* sniffer);
int sniff(Sniffer* sniffer);
