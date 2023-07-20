#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4
struct libnet_ethernet_hdr
{
	u_int8_t ether_dhost[ETHER_ADDR_LEN];
	u_int8_t ether_shost[ETHER_ADDR_LEN];
	u_int16_t ether_type;

};

struct libnet_ip_hdr
{
	u_int8_t ip_dhost[IP_ADDR_LEN];
	u_int8_t ip_shost[IP_ADDR_LEN];
};

void print_ip(u_int8_t *m){
	u_int8_t *p = (m+26);
	printf("Internet protocol source address is : %03d.%03d.%03d.%03d\n",p[0],p[1],p[2],p[3]);
	//printf("\n");
//	printf("Internet protocol destination address is : %03d.%03d.%03d.%03d\n",p[4],p[5],p[6],p[7]);

	printf("Internet protocol destination2 address is : %03d.%03d.%03d.%03d\n",p[4],p[5],p[6],p[7]);

	u_int16_t y1 = (p[8] & 0x00FF) <<8;
	u_int16_t y2 = (p[9] & 0x00FF);
	u_int16_t y3 = y1+y2;
	printf("TCP source port number is : %04d\n",y3);

	u_int16_t y4 = (p[10] & 0x00FF) <<8;
	u_int16_t y5 = (p[11] & 0x00FF);
	u_int16_t y6 = y4+y5;
	printf("TCP destination port number is : %04d\n",y6);




//	printf("TCP destination port number is : %04d\n",{p[10],p[11]};

	printf("\n");
//	uint8_t network_buffer[] = {p[4], p[5], p[6], p[7]};
//	uint32_t* p2 = reinterpret_cast<uint32_t*>(network_buffer);

//	uint32_t b1 = (*p2 & 0xFF000000) >>24;
//	uint32_t b2 = (*p2 & 0x00FF0000) >>8;
//	uint32_t b3 = (*p2 & 0x0000FF00) <<8;
//	uint32_t b4 = (*p2 & 0x000000FF) <<24;

//	printf("Internet protocol destination address is : %d.%d.%d.%d\n",b1,b2,b3,b4);


}

void print_mac(u_int8_t *m){

	printf("Ethernet destination MAC address is : %02x:%02x:%02x:%02x:%02x:%02x\n",m[0],m[1],m[2],m[3],m[4],m[5]);
//	printf("\n");
	printf("Ethernet source MAC address is : %02x:%02x:%02x:%02x:%02x:%02x\n",m[6],m[7],m[8],m[9],m[10],m[11]);
//	printf("\n");
}
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
	//	printf("%u bytes captured\n", header->caplen);
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *) packet;
		struct libnet_ip_hdr *ip_hdr = (struct libnet_ip_hdr *) packet;
		print_mac(eth_hdr->ether_dhost);
		print_ip(ip_hdr->ip_dhost);

	}

	pcap_close(pcap);
}
