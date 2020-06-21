#include "Logger.h"

void create_packet_logs_vector(PacketLog* packet_logs[], int* size) {
    *size = 0;
    *packet_logs = (PacketLog*) malloc(sizeof(PacketLog));
}

void packet_logs_append(PacketLog* packet_logs[], int* size, PacketLog new_log) {
    (*size)++;
    *packet_logs = (PacketLog*) realloc(*packet_logs, sizeof(PacketLog) * (*size));
    (*packet_logs)[(*size) - 1] = new_log;
}


int save_log(
    FILE* logfile,
    struct in_addr ip_addr,
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


int search_log(PacketLog packet_logs[], PacketLog searched_packet, int left_bound, int right_bound) { 
    if (right_bound < left_bound) {
        return -1;
    }

    int middle = (right_bound + left_bound) / 2;

    if (packet_logs[right_bound].ip.s_addr == searched_packet.ip.s_addr) {
        return right_bound;
    }

    if (packet_logs[left_bound].ip.s_addr == searched_packet.ip.s_addr) {
        return left_bound;
    }

    if (searched_packet.ip.s_addr == packet_logs[middle].ip.s_addr) {
        return middle;
    }

    if (searched_packet.ip.s_addr < packet_logs[middle].ip.s_addr) {
        return search_log(packet_logs, searched_packet, left_bound, middle - 1);
    }

    if (searched_packet.ip.s_addr > packet_logs[middle].ip.s_addr) {
        return search_log(packet_logs, searched_packet, middle + 1, right_bound);
    }

    return -1;
}

int sort_logs(PacketLog* packet_logs, int size) {
    qsort(packet_logs, size, sizeof(PacketLog), (int(*) (const void *, const void *)) compare_logs);
}

int compare_logs(const PacketLog* first_log, const PacketLog* second_log) {
    if (first_log->ip.s_addr > second_log->ip.s_addr) {
        return 1;
    } else if (first_log->ip.s_addr < second_log->ip.s_addr) {
        return -1;
    }
    return 0;
}
