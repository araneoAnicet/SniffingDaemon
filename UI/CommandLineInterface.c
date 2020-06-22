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
        printf("Error: the proccess is already running, stop it to change the interface\n");
        printf("\033[0m");
        printf("Type -- help for more details.\n");
        return -1;
    }
    printf("\033[31m");
    printf("Error: seems like this interface is not available on your machine\n");
    printf("\033[0m");        
    return -1;
}