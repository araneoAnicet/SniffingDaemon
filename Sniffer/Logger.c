#include "Logger.h"

int rewrite_logs(char* logfile_name, PacketLog* packet_logs, int top_index) {
    int remove_status = remove(logfile_name);
    int write_status;
    int i;
    if (remove_status == -1) {
        printf("An error occured while deleting log file\n");
        return -1;
    }
    FILE* logfile = fopen(logfile_name, "w");
    if (logfile == NULL) {
        printf("An error occured while creating a new log file\n");
        return -1;
    }
    for (i = 0; i <= top_index; i++) {
        write_status = save_log(
            logfile,
            packet_logs[i].ip,
            packet_logs[i].amount_of_packets,
            packet_logs[i].interface
        );
        if (write_status == -1) {
            printf("An error occured while writing to a new log file\n");
            return -1;
        }
    }
}

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

int read_log(FILE* logfile, PacketLog** packet_logs, int* top_index) {
    *top_index = 0;
    int number_of_spaces = 0;
    PacketLog* temp_logs = (PacketLog*) malloc(sizeof(PacketLog));
    if (temp_logs == NULL) {
        printf("An error occured while allocating memory for logs\n");
        return -1;
    }
    PacketLog temp_log;
    char* ip_addr = '\0';
    char* number_of_packets = '\0';
    char* interface_name = '\0';

    char temp_char;
    while (temp_char = fgetc(logfile) != EOF) {
        if (temp_char == '\n') {
            temp_log.ip = ip_addr;
            temp_log.interface = interface_name;
            temp_log.amount_of_packets = atoi(number_of_packets);
            ip_addr = '\0';
            number_of_packets = '\0';
            interface_name = '\0';
            temp_logs[*top_index] = temp_log;
            (*top_index)++;
            temp_logs = (PacketLog*) realloc(temp_logs, sizeof(temp_logs) * 2);
            if (temp_logs == NULL) {
                printf("An error occured while reallocating memory for logs\n");
                return -1;
            }
            number_of_spaces = 0;
            continue;
        }

        if (temp_char == ' ') {
            number_of_spaces++;
            continue;    
        }
        if (number_of_spaces == 0) {
            strncat(number_of_packets, &temp_char, 1);

        } else if (number_of_spaces == 1) {
            strncat(ip_addr, &temp_char, 1);

        } else if (number_of_spaces == 3) {
            strncat(interface_name, &temp_char, 1);
        }
    }
    *packet_logs = temp_logs;
    return 1;

}

int add_log(PacketLog** packet_logs, PacketLog new_packet, int* new_element_index) {
    int index_of_log = search_log(*packet_logs, new_packet, 0, *new_element_index - 1);
    if (index_of_log == -1) {
        *packet_logs = (PacketLog*) realloc(packet_logs, sizeof(packet_logs) * 2);
        (*packet_logs)[*new_element_index] = new_packet;
        *new_element_index++;
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
