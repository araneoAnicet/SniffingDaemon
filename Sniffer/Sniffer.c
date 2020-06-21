#include "Sniffer.h"

int create_sniffer_socket(Sniffer* sniffer) {
    int socket_fd = socket(
        sniffer->socket.domain,
        sniffer->socket.type,
        sniffer->socket.protocol
        );
    if (socket_fd < 0) {
        printf("An error occured while creating a sniffer socket\n");
        return -1;
    }
    
    socklen_t opt_len = strnlen(sniffer->socket.interface_name, IF_NAMESIZE);
    if (opt_len == IF_NAMESIZE) {
        printf("An error occured while getting interface name size");
        return -1;
    }
    if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, sniffer->socket.interface_name, opt_len) == -1) {
        printf("An error occured while binding\n");
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
    printf("Sniffer is removed successfully!\n");
}


int sniff(Sniffer* sniffer) {
    int buffer_length;
    struct sockaddr_ll source_addr;  // only for determinating packets type
    socklen_t source_addr_len = sizeof(source_addr);
    struct iphdr* ip_headers;

    PacketLog* packet_logs;
    PacketLog new_packet_log;
    int packet_logs_size;
    int searched_index;
    create_packet_logs_vector(&packet_logs, &packet_logs_size);
    
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
            printf("An error occured while receiving packets\n");
            close_sniffer_socket(sniffer);
            return -1;
        }
        if (source_addr.sll_pkttype == PACKET_HOST) {
            ip_headers = (struct iphdr*) (sniffer->socket.buffer + sizeof(struct ethhdr));

            // getting ip from ip header and converting to string
            new_packet_log.amount_of_packets = 1;
            new_packet_log.interface = sniffer->socket.interface_name;
            new_packet_log.ip.s_addr = ip_headers->saddr;

            searched_index = search_log(packet_logs, new_packet_log, 0, packet_logs_size - 1);
            if (searched_index == -1) {
                // if there is new IP address
                packet_logs_append(&packet_logs, &packet_logs_size, new_packet_log);
                sort_logs(packet_logs, packet_logs_size);
            } else {
                // if this IP address has already sent any packets
                packet_logs[searched_index].amount_of_packets += 1;
            }

            // updating log file
            FILE* logfile = fopen(LOG_FILE_NAME, "w");
            if (logfile == NULL) {
                printf("An erro occured while openning log file\n");
                return -1;
            }
            if (save_logs(logfile, packet_logs, packet_logs_size)) {
                return -1;
            }
            fclose(logfile);
        }
    }
    free(packet_logs);
    printf("Removed packet logs from memory\n");
}
