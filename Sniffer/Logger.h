#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#define LOG_FILE_NAME "NetworkSniffing.log"
#define PACKETS_BUFFER_SIZE 1024

typedef struct {
    struct in_addr ip;
    char* interface;
    int amount_of_packets;
} PacketLog;

int save_log(
    FILE* logfile,
    struct in_addr ip_addr,
    int amount_of_packets,
    char* interface_name
);


// A dynamically allocated array of packet logs.
void create_packet_logs_vector(PacketLog* packet_logs[], int* size);
void packet_logs_append(PacketLog* packet_logs[], int* size, PacketLog new_packet);


// removes an old .log file and replaces it with a new .log file
int rewrite_logs(int size, PacketLog packet_logs[], char* logfile_name);

// not asigned pointer of packet_logs and top_index should be given as an argument.
// the function reads the logfile. returns packet_logs array and top_index
int read_log(PacketLog* packet_logs[], int* size, FILE* logfile);

// new_element_index - index where a new log should be added. it is usually top_index + 1
int add_log(PacketLog* packet_logs[], int* size, PacketLog new_packet);

// binary search. Returns an id of the searched packet. Returns -1 if the packet wasn't found.
// left_bound should be equal to 0, right_bound should be equal to the index of the element at the top (size - 1)
int search_log(PacketLog packet_logs[], PacketLog searched_packet, int left_bound, int right_bound);

// quick sort. last_log_index should be equal to the index of the last added element
int sort_logs(PacketLog packet_logs[], int size);

// compares IP addresses of 2 packets. function exists to ensure qsort function works correctly
// returns the result of strcmp function with IP addresses given as the arguments
int compare_logs(const PacketLog* first_log, const PacketLog* second_log);
