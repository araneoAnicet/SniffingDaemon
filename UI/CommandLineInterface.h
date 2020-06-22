#pragma once
#include "../Sniffer/Logger.h"

int start();
int stop();
int show(char* ip);
int select_iface(char* interface);
int statistics(char* interface);
void help();