#include <iostream>
#include <pcap.h>
#include <libnet.h>
#include <vector>
#include <map>
using namespace std;

int main(int argc, char* argv[]) { //<pcap file>
	if (argc < 2) {
		cout << "put <pcap file>" << endl;
		return 0;
	}

	map<string, pair<int,int>> packets_cnt; // ip별 송신,수신 패킷수
    map<string, pair<int,int>> packets_byte; // ip별 송신,수신 패킷 바이트
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_offline(argv[1], errbuf);
	if (pcap == nullptr) {
		cerr << "Error opening pcap file: " << errbuf << endl;
		return 1;
	}

	struct pcap_pkthdr* header;
    const uint8_t* packet;

    while (pcap_next_ex(pcap, &header, &packet) == 1) {
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + LIBNET_IPV4_H);

        string src_ip = inet_ntoa(ip_hdr->ip_src);
        string dst_ip = inet_ntoa(ip_hdr->ip_dst);

        packets_cnt[src_ip].first++; // 송신 패킷 개수 증가
        packets_byte[src_ip].first += header->caplen; // 송신 패킷 크기 합산

        packets_cnt[dst_ip].second++; // 수신 패킷 개수 증가
        packets_byte[dst_ip].second += header->caplen; // 수신 패킷 크기 합산

        //cout << "Source IP: " << src_ip << ", Destination IP: " << dst_ip << ", Packet Size: " << header->caplen << " bytes" << endl;
    }

    pcap_close(pcap);

    for (const auto& m : packets_cnt){
        cout<< "ip : " <<m.first<<"  송신 패킷 수 : "<<m.second.first<<" 개  송신 패킷 바이트 : "<<packets_byte[m.first].first<<" byte  ";
        cout<< "수신 패킷 수 : "<< m.second.second <<" 개  수신 패킷 바이트 : "<<packets_byte[m.first].second<<" byte"<<endl;
    }

    return 0;
}