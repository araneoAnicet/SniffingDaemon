#include "SignalHandlers.h"

void termination_handler(int sig) {
    close_sniffer_socket(global_sniffer);
    remove(CONF_FILE);
    exit(0);
}

void ip_stats_handler(int sig) {
    
}