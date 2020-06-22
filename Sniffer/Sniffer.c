#include "Sniffer.h"

pid_t get_daemon_pid() {
    FILE* conf_file = fopen(CONF_FILE, "r");
    if (conf_file == NULL) {
        return -1;
    }
    char* line = NULL;
    size_t len = 0;
    getline(&line, &len, conf_file);
    return atoi(line);
}

int create_sniffer_socket(Sniffer* sniffer) {
    int socket_fd = socket(
        sniffer->socket.domain,
        sniffer->socket.type,
        sniffer->socket.protocol
        );
    if (socket_fd < 0) {
        error_log("An error occurred while creating a sniffer socket\n");
        return -1;
    }
    
    socklen_t opt_len = strnlen(sniffer->socket.interface_name, IF_NAMESIZE);
    if (opt_len == IF_NAMESIZE) {
        error_log("An error occurred while getting interface name size");
        return -1;
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, sniffer->socket.interface_name, opt_len) == -1) {
        error_log("An error occurred while binding\n");
        return -1;
    }
    sniffer->socket.fd = socket_fd;
    sniffer->socket.buffer = (unsigned char*) malloc(sniffer->socket.buffer_size);
    memset(sniffer->socket.buffer, 0, sniffer->socket.buffer_size);
    return 0;
}

void close_sniffer_socket(Sniffer* sniffer) {
    close(sniffer->socket.fd);
    free(sniffer->socket.buffer);
    free(sniffer->packet_logs);
}


int sniff(Sniffer* sniffer) {
    save_conf(sniffer->socket.interface_name, 1);
    int buffer_length;
    struct sockaddr_ll source_addr;  // only for determinating packets type
    socklen_t source_addr_len = sizeof(source_addr);
    struct iphdr* ip_headers;
    FILE* logfile;
    PacketLog new_packet_log;
    int searched_index;
    
    create_packet_logs_vector(&(sniffer->packet_logs), &(sniffer->packet_logs_size));
    char logfile_name_buffer[120];
    sprintf(logfile_name_buffer, "%s/%s.log", LOGS_FOLDER, sniffer->socket.interface_name);
    logfile = fopen(logfile_name_buffer, "r");
    if (logfile != NULL) {
        if (read_logs(&(sniffer->packet_logs), &(sniffer->packet_logs_size), logfile) == -1) {
            error_log("An error occurred while reading logs\n");
            fflush(logfile);
            fclose(logfile);
            return -1;
        }
        fflush(logfile);
        fclose(logfile);
    }
    
    printf("After file reading.\n");
    
    while (1) {
        buffer_length = recvfrom(
            sniffer->socket.fd,
            sniffer->socket.buffer,
            sniffer->socket.buffer_size,
            0,
            (struct sockaddr*) &source_addr,
            &source_addr_len
        );
        if (buffer_length < 0) {
            error_log("An error occurred while receiving packets\n");
            close_sniffer_socket(sniffer);
            return -1;
        }
        if (source_addr.sll_pkttype == PACKET_HOST) {
            ip_headers = (struct iphdr*) (sniffer->socket.buffer + sizeof(struct ethhdr));

            // getting ip from ip header and converting to string
            new_packet_log.amount_of_packets = 1;
            new_packet_log.interface = sniffer->socket.interface_name;
            new_packet_log.ip.s_addr = ip_headers->saddr;

            searched_index = search_log(sniffer->packet_logs, new_packet_log, 0, sniffer->packet_logs_size - 1);
            if (searched_index == -1) {
                // if there is new IP address
                packet_logs_append(&(sniffer->packet_logs), &(sniffer->packet_logs_size), new_packet_log);
                sort_logs(sniffer->packet_logs, sniffer->packet_logs_size);
            } else {
                // if this IP address has already sent any packets
                (sniffer->packet_logs)[searched_index].amount_of_packets += 1;
            }

        }
    }
}
