#pragma once
#include <stdio.h>


#define LOG_FILE_NAME "NetworkSniffingLogs.log"

int log_status(
    FILE* logfile,
    char ip_addr[],
    int amount_of_packets,
    char* interface_name
);
