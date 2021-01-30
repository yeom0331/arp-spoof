#pragma once
#include "arphdr.h"
#include "ethhdr.h"
#include "mac.h"
#include "ip.h"
#include <pcap.h>

#pragma pack(push, 1)
struct EthArpPacket
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void arp_request(Mac attacker_mac, Ip attacker_ip, Ip sender_ip, pcap_t *handle);
void arp_reply(Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip, pcap_t* handle);

