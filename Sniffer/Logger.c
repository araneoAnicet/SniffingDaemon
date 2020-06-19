#include "Logger.h"

int save_log(
    FILE* logfile,
    char ip_addr[],
    int amount_of_packets,
    char* interface_name
    ) {
    if (fprintf(logfile, "%d %s -> %s\n", amount_of_packets, ip_addr, interface_name) < 0) {
        printf("An error occured while logging\n");
        return -1;
    }
    fflush(logfile);
    return 0;
}

int add_log(PacketLog** packet_logs, PacketLog new_packet, int* array_top_index) {
    int index_of_log = search_log(packet_logs, new_packet, 0, *array_top_index - 1);
    if (index_of_log == -1) {
        *packet_logs = (PacketLog*) realloc(packet_logs, sizeof(packet_logs) * 2);
        (*packet_logs)[*array_top_index] = new_packet;
        *array_top_index++;
        return 1;
    } 
    (*packet_logs)[index_of_log].amount_of_packets++;
    return 1;
}

int search_log(PacketLog* packet_logs, PacketLog searched_packet, int left_bound, int right_bound) { 
    int middle;
    if (right_bound >= left_bound) { 
        middle = left_bound + (right_bound - left_bound) / 2; 
   
        if (strcmp(packet_logs[middle].ip, searched_packet.ip) == 0) {
            return middle;
        }
   
        if (strcpm(packet_logs[middle].ip, searched_packet.ip) > 0) {
            return binarySearch(packet_logs, searched_packet, left_bound, middle - 1);
        } 
        return binarySearch(packet_logs, searched_packet, middle + 1, right_bound); 
    }
  
    // no packets found 
    return -1; 
}

int sort_logs(PacketLog* packet_logs, int last_log_index) {
    qsort(packet_logs, last_log_index + 1, sizeof(PacketLog), (int(*) (const void *, const void *)) compare_logs);
}

int compare_logs(PacketLog first_log, PacketLog second_log) {
    return strcmp(first_log.ip, second_log.ip);
}
