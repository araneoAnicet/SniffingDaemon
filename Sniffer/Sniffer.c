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

inline void print_headers(struct ethhdr* eth) {
    int i;
    printf("\n\n PACKET\n");
    printf("\t Source: ");
    for (i = 0; i < 5; i++) {
        printf("%.2X-", eth->h_source[i]);
    }
    printf("%.2X\n", eth->h_source[5]);
    printf("\t Destination: ");
    for (i = 0; i < 5; i++) {
        printf("%.2X-", eth->h_dest[i]);
    }
    printf("%.2X\n", eth->h_dest[5]);
    printf("\t Protocol : %d\n",eth->h_proto);
}

int sniff(Sniffer* sniffer) {
    int buffer_length;
    struct sockaddr source_addr;
    int source_addr_len = sizeof(source_addr);
    struct ethhdr* eth_headers;
    while (1) {
        buffer_length = recvfrom(
        sniffer->socket.fd,
        sniffer->socket.buffer,
        sniffer->socket.buffer_size,
        0,
        &source_addr,
        (socklen_t*) &source_addr_len
        );

        if (buffer_length < 0) {
            printf("An error occured while receiving packets\n");
            close_sniffer_socket(sniffer);
            return -1;
        }

        eth_headers = (struct ethhdr*) sniffer->socket.buffer;
        print_headers(eth_headers);
    }
}