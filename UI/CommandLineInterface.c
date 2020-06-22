#include "CommandLineInterface.h"

int start() {
    FILE* conf_file = fopen(CONF_FILE, "r");
        if (conf_file != NULL) {
            char* line = NULL;
            size_t len = 0;
            ssize_t read;
            int current_line_index = 0;
            while ((read = getline(&line, &len, conf_file)) != -1) {
                if (current_line_index == 1) {
                    if (atoi(line) == 1) {  // process is currently running
                        return -1;
                    } else {  // process is not running
                        return 0;
                    }
                }
                current_line_index++;
            }
        }
        return 0;  // configuration file does not exist
}

int stop() {
    FILE* conf_file = fopen(CONF_FILE, "r");
        if (conf_file != NULL) {
            char* line = NULL;
            size_t len = 0;
            ssize_t read;
            int current_line_index = 0;
            while ((read = getline(&line, &len, conf_file)) != -1) {
                if (current_line_index == 1) {
                    if (atoi(line) == 1) {  // process is currently running
                        return 0;
                    } else {  // process is not running
                        return -1;
                    }
                }
                current_line_index++;
            }
        }
        return -1;  // configuration file does not exist
}

int show(char* ip) {
    FILE* ip_request_file = fopen(IP_REQUEST_LOG, "w");
    if (ip_request_file == NULL) {
        printf("\033[31m");
        printf("Error: unable to create ip request file...\n");
        printf("\033[0m");
        return -1;
    }
    fprintf(ip_request_file, "%s\n%d", ip, getpid());
    fflush(ip_request_file);
    fclose(ip_request_file);
    kill(get_daemon_pid(), SIGUSR1);
    while (1);  // waiting for interrupt from background process
}