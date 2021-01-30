# Arp Spoofing

## Arp spoofing
* ARP : IP -> MAC 변환해주는 프로토콜
* ARP spoofing : 근거리통신망에서 ARP를 이용하여 상대방의 데이터 패킷을 중간에서 가로채는 기법

## L2 Switch
* L2 switch는 CAM Table 정보를 가지고 있다.
* Mac-Port의 매칭 정보를 가지고 있다.

## HOST
* HOST(Arp table 정보를 갖고 있는 것 모두)는 ARP Table 정보를 가지고 있다.
* IP-MAC의 매칭 정보를 가지고 있다.

## ARP spoofing의 용어
* Attacker : Arp spoofing을 시도하는 호스트
* Sender : Arp spoofing의 패킷 전송자
* Target : Arp spoofing의 패킷 수신자
* flow : sender > attacker > target의 패킷 흐름의 단위
* Original IP Packet : Sender -> Target IP packet
* Spoofed IP Packet : Sender -> Attacker IP packet
* Relay IP Packet : Attacker -> Target IP packet
* Arp infect : Attacker가 Sender를 감염 시키는 행위
* Arp recover : Sender의 감염이 원상복귀되는 현상

## Attacker가 해야할 일
* Attacker는 Sender에게 ARP infect 패킷을 주기적, 혹은 비주기적으로 보내서 감염
* Attacker는 Sender로부터 Spoofed IP packet을 수신하면 Relay IP Packet을 보내야 한다.

## 언제 Sender에서 ARP recover가 되는가
* Sender에서 ARP table 정보가 만료되는 경우 Sender -> ALL(ARP_REQ), Targer -> Sender(ARP_REP)의 ARP Packet에 의해 recover
* Router의 환경에서 외부로부터 Host Scan이 들어 오는 경우 Target(Router) -> Sender의 ARP packet(ARP_REQ)에 의해 Recover

## Swithch 레벨에서 ARP spoofing 탐지의 기본 조건
* 이중화된 Router 환경에서 ARP spoofing 오탐을 하지 말아야 한다.
	- 특정 IP의 MAC이 바뀔 수 있다는 사실 하나만으로 L2 레벨에서 Arp spoofing 탐지는 힘든 일
* Spoofed IP Packet, Relay IP Packet의 탐지뿐 아니라 올바른 라우팅까지 해주어야한다.
	- spoofed Ip packet -> Original Ip packet으로 변경해서 라우팅까지 올바로 할 수 있다면 good

