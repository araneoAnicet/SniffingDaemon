#include "Logger.h"

void create_packet_logs_vector(PacketLog* packet_logs[], int* size) {
    *size = 0;
    *packet_logs = (PacketLog*) malloc(sizeof(PacketLog));
    printf("Allocated size: %d\n", sizeof(PacketLog) * (*size));
}

void packet_logs_append(PacketLog* packet_logs[], int* size, PacketLog new_log) {
    (*size)++;
    *packet_logs = (PacketLog*) realloc(*packet_logs, sizeof(PacketLog) * (*size));
    printf("Allocated size: %d\n", sizeof(PacketLog) * (*size));
    printf("Last index: %d\n", (*size) - 1);
    (*packet_logs)[(*size) - 1] = new_log;
};


int save_log(
    FILE* logfile,
    char* ip_addr,
    int amount_of_packets,
    char* interface_name
    ) {
    if (fprintf(logfile, "%d %s %s\n", amount_of_packets, ip_addr, interface_name) < 0) {
        printf("An error occured while logging\n");
        return -1;
    }
    fflush(logfile);
    return 0;
}


int search_log(PacketLog* packet_logs, PacketLog searched_packet, int left_bound, int right_bound) { 
    int middle;
    printf("Entered search log\n");
    
    if (right_bound >= left_bound) { 
        middle = left_bound + (right_bound - left_bound) / 2; 
        if (strcmp((packet_logs[middle]).ip, searched_packet.ip) == 0) {
            // FIX HERE! DOES NOT REACHb                                                                     n                                                                                                                 rgftb
            printf("After strcmp\n");
            return middle;
        }
   
        if (strcmp(packet_logs[middle].ip, searched_packet.ip) > 0) {
            return search_log(packet_logs, searched_packet, left_bound, middle - 1);
        } 
        return search_log(packet_logs, searched_packet, middle + 1, right_bound); 
    }
  
    // no packets found 
    return -1; 
}

int sort_logs(PacketLog* packet_logs, int top_index) {
    qsort(packet_logs, top_index + 1, sizeof(PacketLog), (int(*) (const void *, const void *)) compare_logs);
}

int compare_logs(PacketLog first_log, PacketLog second_log) {
    return strcmp(first_log.ip, second_log.ip);
}
