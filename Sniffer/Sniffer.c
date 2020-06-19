#include "Sniffer.h"

int get_interface_addr_by_name(Sniffer* sniffer, struct sockaddr** interface_addr) {
    struct sockaddr* result;
    struct ifaddrs* interfaces;
    struct ifaddrs* current_interface;
    if (getifaddrs(&interfaces) == -1) {
        printf("An error occured while getting interfaces information\n");
        return -1;
    }
    current_interface = interfaces;
    while (current_interface != NULL) {
        if (strcmp(current_interface->ifa_name, sniffer->socket.interface_name) == 0) {
            *interface_addr = current_interface->ifa_addr;
            freeifaddrs(interfaces);
            return 0;  // interface address found
        }
        current_interface = current_interface->ifa_next;
    }
    freeifaddrs(interfaces);
    return 1;  // no interface with this name found
}

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

inline void print_headers(struct ethhdr* eth, struct iphdr* iph) {
    int i;
    struct sockaddr_in source_socket, destination_socket;
    memset(&source_socket, 0, sizeof(source_socket));
    memset(&destination_socket, 0, sizeof(destination_socket));
    source_socket.sin_addr.s_addr = iph->saddr;
    destination_socket.sin_addr.s_addr = iph->daddr;
    printf("\n\n PACKET\n");
    printf("\t Source:\n");
    printf("\t\tMAC: ");
    for (i = 0; i < 5; i++) {
        printf("%.2X-", eth->h_source[i]);
    }
    printf("%.2X\n", eth->h_source[5]);
    printf("\t\tIP: %s\n", inet_ntoa(source_socket.sin_addr));
    printf("\t Destination:\n");
    printf("\t\tMAC: ");
    for (i = 0; i < 5; i++) {
        printf("%.2X-", eth->h_dest[i]);
    }
    printf("%.2X\n", eth->h_dest[5]);
    printf("\t\tIP: %s\n", inet_ntoa(destination_socket.sin_addr));
    printf("\t Protocol : %d\n",eth->h_proto);
}

int sniff(Sniffer* sniffer) {
    int buffer_length;
    struct sockaddr_ll source_addr;
    socklen_t source_addr_len = sizeof(source_addr);
    struct ethhdr* eth_headers;
    struct iphdr* ip_headers;

    
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
            eth_headers = (struct ethhdr*) sniffer->socket.buffer;
            ip_headers = (struct iphdr*) (sniffer->socket.buffer + sizeof(struct ethhdr));
            print_headers(eth_headers, ip_headers);
        }
    }
}
