#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>


#define LOG_FILE_NAME "NetworkSniffing.log"
#define ERRORS_LOG_FILE_NAME "Errors.log"
#define PACKETS_BUFFER_SIZE 1024
#define IP_LINE_INDEX 0
#define PACKETS_LINE_INDEX 1
#define INTERFACE_LINE_INDEX 2

typedef struct {
    struct in_addr ip;
    char* interface;
    int amount_of_packets;
} PacketLog;

// saves a packet log into log file
int save_log(
    FILE* logfile,
    struct in_addr ip_addr,
    int amount_of_packets,
    char* interface_name
);


// saves packet logs from packet_logs array into log file
int save_logs(
    FILE* logfile,
    PacketLog* packet_logs,
    int size
);

// logs errors into .log file
void error_log(char* error_message);

// A dynamically allocated array of packet logs.
void create_packet_logs_vector(PacketLog* packet_logs[], int* size);
void packet_logs_append(PacketLog* packet_logs[], int* size, PacketLog new_packet);



// not asigned pointer of packet_logs and top_index should be given as arguments.
// the function reads the logfile. returns packet_logs array and top_index
int read_logs(PacketLog* packet_logs[], int* size, FILE* logfile);

// adds a new packet to packet_logs array
int add_log(PacketLog* packet_logs[], int* size, PacketLog new_packet);

// binary search. Returns an id of the searched packet. Returns -1 if the packet wasn't found.
// left_bound should be equal to 0, right_bound should be equal to the index of the element at the top (size - 1)
int search_log(PacketLog packet_logs[], PacketLog searched_packet, int left_bound, int right_bound);

// quick sort. sorts packet_logs
int sort_logs(PacketLog packet_logs[], int size);

// compares IP addresses of 2 packets. function exists to ensure qsort function works correctly
// returns 0 if addresses are the same
// returns 1 if first_log address is bigger then second_logs' address
// returns -1 if first_log address is less then second_logs' address
int compare_logs(const PacketLog* first_log, const PacketLog* second_log);
