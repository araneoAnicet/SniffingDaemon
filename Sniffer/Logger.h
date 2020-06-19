#pragma once
#include <stdio.h>


#define LOG_FILE_NAME "NetworkSniffingLogs.log"
#define PACKETS_BUFFER_SIZE 1024

typedef struct {
    char* ip;
    char* interface;
    int amount_of_packets;
} PacketLog;

PacketLog packet_logs[PACKETS_BUFFER_SIZE];

int save_log(
    FILE* logfile,
    char ip_addr[],
    int amount_of_packets,
    char* interface_name
);

