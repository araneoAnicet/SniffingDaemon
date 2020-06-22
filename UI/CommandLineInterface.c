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