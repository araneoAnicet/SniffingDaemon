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
    if (fprintf(logfile, "%s\n%d\n%s\n", inet_ntoa(ip_addr), amount_of_packets, interface_name) < 0) {
        printf("An error occurred while saving logs\n");
        return -1;
    }
    fflush(logfile);
    return 0;
}

int save_logs(FILE* logfile, PacketLog* packet_logs, int size) {
    for (int i = 0; i < size; i++) {
        if (save_log(logfile, packet_logs[i].ip, packet_logs[i].amount_of_packets, packet_logs[i].interface) == -1) {
            return -1;
        }
    }
    return 0;
}

int read_logs(PacketLog* packet_logs[], int* size, FILE* logfile) {
    int line_index = 0;
    PacketLog temp_log;
    struct in_addr temp_addr;
    int in_addr_status;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, logfile)) != -1) {
        if (line_index == IP_LINE_INDEX) {
            line[strlen(line) - 1] = 0;  // removing '\n' char at the end
            in_addr_status = inet_aton(line, &temp_addr);
            if (in_addr_status == -1) {
                printf("An error occurred while parsing .log file IP address\n");
                return -1;
            }
            temp_log.ip.s_addr = temp_addr.s_addr;
        }
        if (line_index == PACKETS_LINE_INDEX) {
            temp_log.amount_of_packets = atoi(line);
        }
        if (line_index == INTERFACE_LINE_INDEX) {
            line[strlen(line) - 1] = 0;
            temp_log.interface = line;
            line_index = IP_LINE_INDEX;
            packet_logs_append(packet_logs, size, temp_log);
            continue;
        }
        line_index++;
    }
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
