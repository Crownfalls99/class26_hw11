#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <ncursesw/curses.h>
#include <locale.h>

#define MAC_LEN 	6
#define SSID_LEN	32
#define MAX_ENTRY	1000

#pragma pack(push, 1)
struct RadiotapHdr {
	u_int8_t version;
	u_int8_t pad;
	u_int16_t len;
	u_int32_t present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct BeaconHdr {
	struct {
		u_int16_t frame;
		u_int16_t duration;
		u_int8_t dmac[MAC_LEN];
		u_int8_t smac[MAC_LEN];
		u_int8_t bssid[MAC_LEN];
		u_int16_t seq;
	} MacHdr;
	u_int64_t timestamp;
	u_int16_t interval;
	u_int16_t capability;
	u_int8_t eid;
	u_int8_t slen;
	char ssid[SSID_LEN];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct BFrame {
	struct RadiotapHdr radio;
	struct BeaconHdr beacon;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct entry {
	u_int8_t bssid[MAC_LEN];
	int beacons;
	int slen;
	char ssid[SSID_LEN + 1];
};
#pragma pack(pop)

struct entry list[MAX_ENTRY];
int head = 0;

int entryCompare(const void* _a, const void* _b) {
        struct entry* a = (struct entry*) _a;
        struct entry* b = (struct entry*) _b;

        return memcmp((struct entry*)a->bssid, (struct entry*)b->bssid, MAC_LEN);
}

bool parsePkt(struct entry* newbf, const u_char* packet) { 
	BFrame* fix = (BFrame*) packet;
	u_char* ptr = (u_char*) packet;

	if (*ptr != (u_int8_t)0x00) return false;

	ptr += (int)(fix->radio.len);
	if (*ptr != (u_int8_t)0x80) return false;
	
	BeaconHdr* tmp = (BeaconHdr*) ptr;
	memcpy(newbf->bssid, tmp->MacHdr.bssid, MAC_LEN);
	newbf->beacons = 1;
	newbf->slen = (int)tmp->slen;
	memcpy(newbf->ssid, tmp->ssid, (size_t)newbf->slen);
	return true;
}    

void printList() {
	mvprintw(0, 0, "BSSID\t\t\t\tBeacons\t\tESSID\n\n");
	for (int i = 0; i < head; i++) {
		struct entry* entry = &list[i];
		
		for (int i = 0; i < MAC_LEN - 1; i++)
			printw("%02hhX:", entry->bssid[i]);
		printw("%02hhX\t\t", entry->bssid[MAC_LEN - 1]);
		
		printw("%d\t\t", entry->beacons);

		if (strlen(entry->ssid) == 0)
			printw("<length: %d>\n", entry->slen);
		else
			printw("%s\n", entry->ssid);
	}
}

void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump wlan0\n");
}

int main(int argc, char* argv[]) {
	const char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	if (argc != 2) {
		usage();
		exit(1);
	}

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live failed\n");
		exit(1);
	}

	setlocale(LC_CTYPE, "ko_KR.utf-8");
	initscr();
	printw("BSSID\t\t\t\tBeacons\t\tESSID\n\n");
	refresh();
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == -1 || res == -2) {
			fprintf(stderr, "pcap_next_ex failed\n");
			exit(1);
		}
		if (res == 0) continue;
		
		memset(&list[head], 0, sizeof(entry));
		if (header->caplen < 36 || !parsePkt(&list[head], packet)) continue;
		struct entry* ptr = (struct entry*) bsearch(&list[head], list, (size_t) head, sizeof(entry), entryCompare);
		if (ptr == nullptr) {
			head++;
			qsort(list, head, sizeof(entry), entryCompare);
		} else ptr->beacons++;
		
		printList();
		refresh();
	}
	endwin();
	pcap_close(handle);
	return 0;
}

