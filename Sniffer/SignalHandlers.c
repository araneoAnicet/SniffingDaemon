#include "SignalHandlers.h"

void termination_handler(int sig) {
    close_sniffer_socket(global_sniffer);
    remove(CONF_FILE);
    exit(0);
}

void ip_stats_handler(int sig) {
    char* ip_request_file_name = "/var/log/snifferd/ip_request.log";
    FILE* ip_request_file = fopen(ip_request_file_name, "r");
    int search_index;

    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    int current_line_index = 0;
    
    PacketLog temp_log;
    temp_log.interface = global_sniffer->socket.interface_name;
    pid_t sender_pid;
    while ((read = getline(&line, &len, ip_request_file)) != -1) {
        if (current_line_index == 0) {
                line[strlen(line) - 1] = 0;
                temp_log.ip.s_addr = inet_aton(line);
            } else {
                sender_pid = atoi(line);
            }
            current_line_index++;
        }
    
    search_index = search_log(
        global_sniffer->packet_logs,
        temp_log,
        0,
        global_sniffer->packet_logs_size - 1
        );
    if (search_index == -1) {
        remove("/var/log/snifferd/ip_request.log");
        kill(sender_pid, SIGUSR1);
        return;
    }
    fclose(ip_request_file);
    ip_request_file = fopen(ip_request_file_name, "w");
    fprintf("%d", (global_sniffer->packet_logs)[search_index].amount_of_packets);
    fflush(ip_request_file);
    fclose(ip_request_file);
    kill(sender_pid, SIGUSR1);
}