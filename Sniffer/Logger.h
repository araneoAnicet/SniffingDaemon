#pragma once
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>


#define LOG_FILE_NAME "NetworkSniffing.log"
#define PACKETS_BUFFER_SIZE 1024

typedef struct {
    char* ip;
    char* interface;
    int amount_of_packets;
} PacketLog;

int save_log(
    FILE* logfile,
    char ip_addr[],
    int amount_of_packets,
    char* interface_name
);

// not asigned pointer of packet_logs and top_index should be given as an argument.
// the function reads the logfile. returns packet_logs array and top_index
int read_log(FILE* logfile, PacketLog** packet_logs, int* top_index);

// array_top - index where a new log should be added.
int add_log(PacketLog** packet_logs, PacketLog new_packet, int* array_top_index);

// binary search. Returns an id of the searched packet. Returns -1 if the packet wasn't found.
// left_bound should be equal to 0, right_bound should be equal to the index of the element at the top
int search_log(PacketLog* packet_logs, PacketLog searched_packet, int left_bound, int right_bound);

// quick sort. last_log_index should be equal to the index of the last added element
int sort_logs(PacketLog* packet_logs, int last_log_index);

// compares IP addresses of 2 packets. function exists to ensure qsort function works correctly
// returns the result of strcmp function with IP addresses given as the arguments
int compare_logs(PacketLog first_log, PacketLog second_log);
