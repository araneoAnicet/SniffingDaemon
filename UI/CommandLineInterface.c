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

int select_iface(char* interface_name) {
    if (check_if_interface_is_available(interface_name) == 0) {
        pid_t pid = get_daemon_pid();
        if (pid == -1) {
            save_conf(interface_name, 0);  // just changes the configurations
            printf("\033[0;32m");
            printf("Success! Your current interface is %s\n", interface_name);
            printf("\033[0m");
            return 0;
        }
        printf("\033[31m");
        printf("Error: the process is already running, stop it to change the interface\n");
        printf("\033[0m");
        printf("Type -- help for more details.\n");
        return -1;
    }
    printf("\033[31m");
    printf("Error: seems like this interface is not available on your machine\n");
    printf("\033[0m");        
    return -1;
}

int statistics(char* interface) {
    if (get_daemon_pid() != -1) {
        printf("\033[31m");
        printf("Error: background process is running, you should stop it to see the statistics.\n");
        printf("\033[0m");
        return -1;
    }
    char path[60];
    sprintf(path, "%s/%s.log", LOGS_FOLDER, interface);
    FILE* logfile = fopen(path, "r");
    if (logfile == NULL) {
        printf("\033[31m");
        printf("Error: No logs for such interface\n");
        printf("\033[0m");
        return -1;
    }
    printf("\033[0;33m");
    printf("IP -> PACKETS (INTERFACE)\n");
    printf("\033[0m");
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    int line_counter = 0;

    while ((read = getline(&line, &len, logfile)) != -1) {
        if (line_counter == 0) {
            line[strlen(line) - 1] = 0;
            printf("%s ", line);
        }
        if (line_counter == 1) {
            line[strlen(line) - 1] = 0;
            printf("-> %s ", line);
        }
        if (line_counter == 2) {
            line[strlen(line) - 1] = 0;
            printf("(%s)\n", line);
            line_counter = 0;
            continue;
        }
        line_counter++;
    }
    return 0;
}

void help_start() {
    printf("START:\n");
    printf("\033[0;33m");
    printf("USAGE: snifferd start\n");
    printf("\033[0m");
    printf("starts the sniffing process\n");
    printf("\n");
}

void help_stop() {
    printf("STOP:\n");
    printf("\033[0;33m");
    printf("USAGE: snifferd stop\n");
    printf("\033[0m");
    printf("terminates the running process\n");
    printf("\n");
}


void help_show() {
    printf("SHOW:\n");
    printf("\033[0;33m");
    printf("USAGE: snifferd show [ip] count\n");
    printf("\033[0m");
    printf("shows ip statistics in the running process\n");
    printf("\n");
}

void help_select() {
    printf("SELECT:\n");
    printf("\033[0;33m");
    printf("USAGE: snifferd select iface [interface]\n");
    printf("\033[0m");
    printf("changes configuration settings. The interface can selected only if process is not running\n");
    printf("\n");
}

void help_statistics() {
    printf("STAT:\n");
    printf("\033[0;33m");
    printf("USAGE: snifferd stat [interface]\n");
    printf("\033[0m");
    printf("shows the statistics for a particular interface. The statistics is written after process stopping\n");
    printf("\n");
}
void help() {
    printf("snifferd:\n");
    help_start();
    help_stop();
    help_show();
    help_select();
    help_statistics();
}