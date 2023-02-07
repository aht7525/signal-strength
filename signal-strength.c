#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

void usage() {
	printf("syntax : signal-strength <interface> <mac>\n");
	printf("sample : signal-strength mon0 00:11:22:33:44:55\n");
}

typedef struct {
	char* dev_;
	char* mac_;
} Param;

Param param = {
};

void low(char *ptr){
	for(int i = 0;i<strlen(ptr);i++){
		ptr[i] = tolower(ptr[i]);
	}
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->mac_ = argv[2];
	return true;
}

//Beacon_frame subtype -> 8

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	low(param.mac_);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	int header_length = 0;
	unsigned int present_flag;	
	char ta[20] = {0,};
	char arr[40] = {0,};
	int c;
	unsigned int antena_strength = 0;
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		header_length = packet[2]+packet[3]*0x100;
		present_flag = packet[4]+(packet[5]<<8)+(packet[6]<<16)+(packet[7]<<24);
		do
   		{
	        	arr[c++] = present_flag%2;
        		present_flag /= 2;
		} while (present_flag != 0); // present_flag -> 0b
		if(packet[header_length] == 0x80){ //Beacon_packet!
			sprintf(ta,"%02x:%02x:%02x:%02x:%02x:%02x",packet[header_length+10],packet[header_length+11],packet[header_length+12],packet[header_length+13],packet[header_length+14],packet[header_length+15]); //ta
			if(!strncmp(param.mac_,ta,17)){ // ta == mac_
				if(arr[5] == 1) {//dbm antena is enable 31->ext, 0->mac_timestamp, 1->flags, 2->rate(but it have 1byte),
					int antena_idx = 4+4+arr[31]*4+arr[0]*8+arr[1]+1+4*arr[3]+4*arr[4];
					antena_strength = 0x100-packet[antena_idx]; //check ext, mac_timestamp,flag,rate,channel
					printf("ta : %s, Antena Signal : -%hhd\n",ta,antena_strength);
				}
			}
		}
		memset(ta,0,20);
		memset(arr,0,20);
		header_length = 0;
		present_flag = 0;
		c = 0;
	}
	pcap_close(pcap);
}
