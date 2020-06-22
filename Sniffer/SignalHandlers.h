#pragma once
#include "Sniffer.h"
#include <sys/signal.h>

void termination_handler(int sig);
void ip_stats_handler(int sig);
void ip_stats_response_handler(int sig);