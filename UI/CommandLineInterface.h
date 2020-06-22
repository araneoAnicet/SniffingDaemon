#pragma once
#include "../Sniffer/Logger.h"
#include "../Sniffer/Sniffer.h"
#include <sys/signal.h>
#include <stdio.h>
#include <unistd.h>

int start();
int stop();
int show(char* ip);
int select_iface(char* interface_name);
int statistics(char* interface);
void help();
void help_start();
void help_stop();
void help_show();
void help_select();
void help_statistics();