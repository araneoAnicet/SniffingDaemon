#include "Sniffer/Sniffer.h"
#include "Sniffer/Logger.h"
#include "UI/CommandLineInterface.h"
//#include "Sniffer/SignalHandlers.h"
#include <sys/signal.h>
#include <stdio.h>


void ip_stats_handler(int sig) {
    FILE* ip_request_file = fopen(IP_REQUEST_LOG, "r");
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
                inet_aton(line, &(temp_log.ip));
            } else {
                sender_pid = atoi(line);
            }
            current_line_index++;
        }
    fflush(ip_request_file);
    fclose(ip_request_file);
    search_index = search_log(
        global_sniffer->packet_logs,
        temp_log,
        0,
        global_sniffer->packet_logs_size - 1
        );
    if (search_index == -1) {
        remove(IP_REQUEST_LOG);
        kill(sender_pid, SIGUSR1);
        return;
    }
    ip_request_file = fopen(IP_REQUEST_LOG, "w");
    fprintf(ip_request_file, "%d", (global_sniffer->packet_logs)[search_index].amount_of_packets);
    fflush(ip_request_file);
    fclose(ip_request_file);
    kill(sender_pid, SIGUSR1);
}

void ip_stats_response_handler(int sig) {
    FILE* ip_request_response_file = fopen(IP_REQUEST_LOG, "r");
    if (ip_request_response_file == NULL) {
        printf("NO PACKETS RECEIVED FROM THIS IP\n");
        exit(0);
    }
    char* line = NULL;
    size_t len = 0;
    getline(&line, &len, ip_request_response_file);
    fflush(ip_request_response_file);
    fclose(ip_request_response_file);
    printf("PACKETS RECEIVED FROM THIS IP: %s\n", line);
    remove(IP_REQUEST_LOG);
    exit(0);
}

void termination_handler(int sig) {
    // saving to log files
    FILE* logfile;
    char logfile_name_buffer[120];
    sprintf(logfile_name_buffer, "%s/%s.log", LOGS_FOLDER, global_sniffer->socket.interface_name);
    logfile = fopen(logfile_name_buffer, "w");
    if (logfile == NULL) {
        error_log("An error occurred while opening interface log file\n");
        return;
    }
    if (save_logs(logfile, global_sniffer->packet_logs, global_sniffer->packet_logs_size)) {
        return;
    }
    fflush(logfile);
    fclose(logfile);
    save_conf(global_sniffer->socket.interface_name, 0);
    exit(0);
}


int start_background_process() {
    pid_t pid; 
    pid = fork();
    if (pid < 0) {
        printf("\033[31m");
        printf("Failed to create child process\n");
        exit(EXIT_FAILURE);
        printf("\033[0m");
    }

    // child
    if (pid == 0) {
        pid_t sid = setsid();
        if (sid < 0) {
            printf("Failed to set a new session\n");
            exit(EXIT_FAILURE);
        }
        umask(0);
        chdir("/");
        
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        
        signal(SIGTERM, termination_handler);
        signal(SIGUSR1, ip_stats_handler);

        create_sniffer_socket(global_sniffer);
        sniff(global_sniffer);
        close_sniffer_socket(global_sniffer);
        return 0;
        } else if (pid > 0) {  // parent
                printf("\033[0;32m");
                printf("Sniffing is activated!\n");
                printf("\033[0m");
                return 0;
        }
}


int main(int argc, char* argv[]) {
    if (check_folder()) {
        printf("Error: could not create a folder\n");
        return -1;
    }
    Sniffer sniffer;
    sniffer.socket.buffer_size = DEFAULT_BUFFER_SIZE;
    sniffer.socket.interface_name = "eth0";
    sniffer.socket.domain = AF_PACKET;
    sniffer.socket.type = SOCK_RAW;
    sniffer.socket.protocol = htons(ETH_P_ALL);
    global_sniffer = &sniffer;

    if (argc < 2) {
        printf("\033[31m");
        printf("Error: not enough arguments.\n");
        printf("\033[0m");
        printf("Type -- help for more details.\n");
        return -1;
    }

    // start command
    if (strcmp(argv[1], "start") == 0) {
        if (argc == 3 && (strcmp(argv[2], "--help") == 0)) {
            help_start();
            return 0;
        }
        if (start() == 0) {

            start_background_process();
            
        } else {
            printf("\033[31m");
            printf("Error: the process is already running...\n");
            printf("\033[0m");
            printf("Type -- help for more details.\n");
            return -1;
        }
    }

    // stop command
    if (strcmp(argv[1], "stop") == 0) {
        if (argc == 3 && (strcmp(argv[2], "--help") == 0)) {
            help_stop();
            return 0;
        }
        if (stop() == 0) {
        pid_t daemon_pid = get_daemon_pid();
        if (daemon_pid == -1) {
            printf("\033[31m");
            printf("Error: the process is not running...\n");
            printf("\033[0m");
            printf("Type -- help for more details.\n");
            return -1;
        }
        kill(daemon_pid, SIGTERM);
        printf("\033[0;32m");
        printf("The process of sniffing is terminated successfully\n");
        printf("\033[0m");
        printf("Type `snifferd stat [iface]` for statistics.\n");
        printf("Type -- help for more details.\n");
        return 0;
        } else {
            printf("\033[31m");
            printf("Error: the process is not running...\n");
            printf("\033[0m");
            printf("Type -- help for more details.\n");
            return -1;
            }
        }

    // show [ip] count command
    if ((strcmp(argv[1], "show") == 0)) {
        if (argc == 3 && (strcmp(argv[2], "--help") == 0)) {
            help_show();
            return 0;
        }
        if (argc == 4) {
            if ((strcmp(argv[3], "count") == 0)) {
                if (stop() == 0) {
                    signal(SIGUSR1, ip_stats_response_handler);  // response from daemon
                    show(argv[2]);
                }
            }
        }
        printf("\033[31m");
        printf("Error: did you forget to specify the interface or add a `count` keyword?\n");
        printf("\033[0m");
        printf("Type -- help for more details.\n");
        return -1;
    }

    // select [iface] command
    if (strcmp(argv[1], "select") == 0) {
        if (argc == 3 && (strcmp(argv[2], "--help") == 0)) {
            help_select();
            return 0;
        }
        if (argc == 4) {
            if (strcmp(argv[2], "iface") == 0) {
                return select_iface(argv[3]);
            }
        }
        printf("\033[31m");
        printf("Error: did you forget to specify the interface or add a `iface` keyword?\n");
        printf("\033[0m");
        printf("Type -- help for more details.\n");
        return -1;
    }

    // stat [iface] command
    if (strcmp(argv[1], "stat") == 0) {
        if (argc == 3 && (strcmp(argv[2], "--help") == 0)) {
            help_statistics();
            return 0;
        }
        if (argc == 3) {
            return statistics(argv[2]);
        }
        printf("\033[31m");
        printf("Error: did you forget to specify the interface\n");
        printf("\033[0m");
        printf("Type -- help for more details.\n");   
        return -1;
    }
    if (argc == 2 && (strcmp(argv[1], "--help") == 0)) {
        help();
        return 0;
    }
    
    printf("\033[31m");
    printf("Error: unknown command\n");
    printf("\033[0m");
    printf("Type -- help for more details.\n");
    return -1;
}
