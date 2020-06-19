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
