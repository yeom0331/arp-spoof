#include "get_attackerinfo.h"

Mac get_mymac(char *dev) {
    struct ifreq ifr;
    int fd= socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < -1) {
        perror("socketopen error\n");
        exit(0);
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr)<0) {
        perror("ioctl error\n");
        exit(0);
    }
    else {
        return Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    }
}

Ip get_myip(char *dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < -1) {
        perror("socketopen error\n");
        exit(0);
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    if(ioctl(fd, SIOCGIFADDR, &ifr)<0) {
        perror("ioctl error\n");
        exit(0);
    }
    else {
        return Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    }
}
