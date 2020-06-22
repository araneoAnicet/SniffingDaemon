#include "Sniffer/Sniffer.h"
#include "Sniffer/Logger.h"
#include "UI/CommandLineInterface.h"
#include "Sniffer/SignalHandlers.h"
#include <sys/signal.h>

int main(int argc, char* argv[]) {
    if (check_folder()) {
        printf("Error: could not create a folder\n");
        return -1;
    }
    Sniffer sniffer;
    sniffer.socket.buffer_size = DEFAULT_BUFFER_SIZE;
    sniffer.socket.interface_name = "wlan0";
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
        if (start() == 0) {

            // creating background process
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
                
                create_sniffer_socket(&sniffer);
                sniff(&sniffer);
                close_sniffer_socket(&sniffer);
                return 0;
            } else if (pid > 0) {  // parent
                printf("\033[0;32m");
                printf("%s sniffing is activated\n", sniffer.socket.interface_name);
                printf("\033[0m");
                printf("Type stat %s to see the statistics\n", sniffer.socket.interface_name);
            }
        } else {
            printf("\033[31m");
            printf("Error: the process is already running...\n");
            printf("\033[0m");
            printf("Type -- help for more details.\n");
        }
    }

    // stop command
    if (strcmp(argv[1], "stop") == 0) {
        if (stop() == 0) {
        FILE* conf_file = fopen(CONF_FILE, "r");
        char* line = NULL;
        size_t len = 0;
        int current_line_index = 0;
        getline(&line, &len, conf_file);
        kill(atoi(line), SIGTERM);
        printf("\033[0;32m");
        printf("The process of sniffing is terminated successfully\n");
        printf("\033[0m");
        } else {
            printf("\033[31m");
            printf("Error: the process is not running...\n");
            printf("\033[0m");
            printf("Type -- help for more details.\n");
        }
    }
}
