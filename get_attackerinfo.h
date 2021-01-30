#pragma once

#include "mac.h"
#include "ip.h"
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <pcap.h>

Mac get_mymac(char *dev);
Ip get_myip(char *dev);
