#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

static void skeleton_daemon()
{
    pid_t pid; 
    pid_t sid;

    pid = fork();
    
    if (pid < 0)
        printf("Failed to create child process\n");
        exit(EXIT_FAILURE);

    if (pid > 0)
        exit(EXIT_SUCCESS);
    
    sid = setsid();
    if (setsid() < 0)
        printf("Failed to set a new session\n");
        exit(EXIT_FAILURE);
    
    umask(0);
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}
