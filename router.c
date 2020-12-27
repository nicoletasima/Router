#include "skel.h"

/* 
Structura pentru o intrare in tabela de rutare 
*/
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

/*
Structura pentru o intrare in tabela ARP
*/
struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

struct route_table_entry *rtable; 		
int rtable_size;						

struct arp_entry *arp_table;
int arp_size;

/*
Comparatorul pentru functia de sortare
*/
int cmp(const void *a, const void *b) {
	struct route_table_entry *r1 = (struct route_table_entry*)a;
	struct route_table_entry *r2 = (struct route_table_entry*)b;

	if (r1->prefix == r2->prefix) {
		if (r1->mask < r2->mask)
			return 1;
		if (r1->mask > r2->mask)
			return -1;
	}
	return r1->prefix - r2->prefix;
}

/*
Functia de parsare pentru tabela de rutare
fgets iar fiecare linie din fisier, iar cu ajutorul lui strtok se ia fiecare adresa
si se transforma in format uint32 folosind inet_pton
*/
struct route_table_entry* parse_rtable() {
	FILE *fp = fopen("rtable.txt", "r");
	int i = 0;
	int dim = 100;
	char line[70] = "";

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (i == dim) {
			dim = dim * 2;
			rtable = realloc(rtable, dim * sizeof(struct route_table_entry));
		}
		char *token;
		token = strtok(line, " ");
		inet_pton(AF_INET, token, &rtable[i].prefix);
		token = strtok(NULL, " ");
		inet_pton(AF_INET, token, &rtable[i].next_hop);	
		token = strtok(NULL, " ");
		inet_pton(AF_INET, token, &rtable[i].mask);
		token = strtok(NULL, " ");
		rtable[i].interface = atoi(token);
		i++;
	}

	fclose(fp);
	rtable_size = i;

	return rtable;
}

/*
Functia de parsare pentru ARP static
*/
void parse_arp_table() {
	FILE *fp = fopen("arp_table.txt", "r");
	int i = 0;
	char line[70] = "";

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *token;
		token = strtok(line, " ");
		arp_table[i].ip = inet_addr(token);
		token = strtok(NULL, " ");
		int check = hwaddr_aton(token, arp_table[i].mac);
		DIE(check == -1, "NO ARP!");
		i++;
	}

	arp_size = i;
	fclose(fp);
}

/*
Functia care calculeaza checksum
*/
uint16_t ip_checksum(void* vdata,size_t length) {	
	char* data=(char*)vdata;

	uint64_t acc=0xffff;
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	return htons(~acc);
}

/* 
Functia get_best_route cauta folsind binary search intrarea potrivita in tabela de rutare
cu masca cea mai mare
*/
struct route_table_entry *get_best_route(__u32 dest_ip) {
	int l  = 0;
	int r = rtable_size - 1;
	
	while (l <= r) {
		int mid = (l + r) / 2;
		if ((rtable[mid].mask & dest_ip) == (rtable[mid].prefix)) {
			while (rtable[mid].prefix == rtable[mid - 1].prefix)
				mid--;
			return &rtable[mid];
		}
		if ((rtable[mid].mask & dest_ip) > rtable[mid].prefix) {
			l = mid + 1;
		} else {
			r = mid - 1;
		}
	}

	return NULL;

}

struct arp_entry *get_arp_entry(__u32 ip) {
	int index = -1;

    for (int i = 0; i < arp_size; i++) {
    	if (ip == arp_table[i].ip) {
    		index = i;
    	}
    }
    if (index != -1)
    	return &arp_table[index];
    return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	init();
	rtable = (struct route_table_entry*)malloc(100 * sizeof(struct route_table_entry));
	arp_table = (struct arp_entry*)malloc(50 * sizeof(struct arp_entry));
	DIE((rtable == NULL), "memory");

	parse_rtable();		// parsare tabela de rutare
	parse_arp_table();	// parsare tabela arp

	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmp); // sortare tabela de rutare


	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload; 	// extrag headerul ethernet
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));		// extrag header IP
		struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));	// extrag header ICMP

		int packet_sent = 0;	// check pachet deja trimis


		if (icmp_hdr->type == ICMP_ECHO && packet_sent == 0) {		// daca tipul pachetului este ICMP_ECHO

			for (int i = 0; i < ROUTER_NUM_INTERFACES && packet_sent == 0; i++) {	// for prin interfetele ruterului

				uint32_t int_ip;
				inet_pton(AF_INET, get_interface_ip(i), &int_ip);

				if (int_ip == ip_hdr->daddr) {			// verific daca aceste era ruterul destinatie
					m.len = sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr);
					__u32 swap = ip_hdr->daddr;
					ip_hdr->daddr = ip_hdr->saddr;
					ip_hdr->saddr = swap;

					u_char addr_swap[6];
					printf("\n");
					memcpy(addr_swap, eth_hdr->ether_dhost, 6);
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, addr_swap, 6);
				
					ip_hdr->ttl = 64;
					ip_hdr->protocol = IPPROTO_ICMP;
					ip_hdr->check = 0;
					ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
					
					icmp_hdr->type = ICMP_ECHOREPLY;	
					icmp_hdr->code = 0;		// ICMP_NET_UNREACH
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

					struct route_table_entry *route_back = get_best_route(ip_hdr->daddr);
					send_packet(route_back->interface, &m);
					packet_sent = 1;
					//continue;
				}

			}
		}

		if (packet_sent == 1)	// daca s-a trimis un pachet 
			continue;

		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != 0) {	// verificare daca suma de control este cea buna
			continue;
		
		}

		if (ip_hdr->ttl <= 1) {		// verificare daca ttl-ul pachetului mai este valabil
			packet reply_packet;
			reply_packet.len = sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr);
			reply_packet.interface = m.interface;


			struct ether_header *reply_ether = (struct ether_header *)reply_packet.payload;
			struct iphdr *reply_iphdr = (struct iphdr *)(reply_packet.payload + sizeof(struct ether_header));
			struct icmphdr *reply_icmp = (struct icmphdr *)(reply_packet.payload + sizeof(struct ether_header) + sizeof(struct iphdr));


			memcpy(reply_ether->ether_dhost, eth_hdr->ether_shost, 6);
			memcpy(reply_ether->ether_shost, eth_hdr->ether_dhost, 6);
			reply_ether->ether_type =  htons(ETHERTYPE_IP);  

			reply_iphdr->ihl = sizeof(struct iphdr) / sizeof(uint32_t);
			reply_iphdr->version = 4;
			reply_iphdr->tos = 0;
			reply_iphdr->tot_len = htons(reply_packet.len);
			reply_iphdr->id = 1;
			reply_iphdr->frag_off = 0;
			reply_iphdr->ttl = 64;
			reply_iphdr->protocol = 1;
			reply_iphdr->daddr = ip_hdr->saddr;
			reply_iphdr->saddr = ip_hdr->daddr;
			reply_iphdr->check = 0;
			reply_iphdr->check = ip_checksum(reply_iphdr, sizeof(struct iphdr));

			reply_icmp->type = ICMP_TIME_EXCEEDED;
			reply_icmp->code = 0;
			reply_icmp->un.echo.id = htons(getpid());
			reply_icmp->checksum = 0;
			reply_icmp->checksum = ip_checksum(reply_icmp, sizeof(struct icmphdr));

			send_packet(reply_packet.interface, &reply_packet);
			continue;

		}

		struct route_table_entry *rentry = get_best_route(ip_hdr->daddr);		// se verifica daca s-a gasit destinatie valida in rtable
		if (rentry == NULL) {
			packet reply_packet;
			reply_packet.len = sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr);
			reply_packet.interface = m.interface;


			struct ether_header *reply_ether = (struct ether_header *)reply_packet.payload;
			struct iphdr *reply_iphdr = (struct iphdr *)(reply_packet.payload + sizeof(struct ether_header));
			struct icmphdr *reply_icmp = (struct icmphdr *)(reply_packet.payload + sizeof(struct ether_header) + sizeof(struct iphdr));


			memcpy(reply_ether->ether_dhost, eth_hdr->ether_shost, 6);
			memcpy(reply_ether->ether_shost, eth_hdr->ether_dhost, 6);
			reply_ether->ether_type = htons(ETHERTYPE_IP);

			reply_iphdr->ihl = sizeof(struct iphdr) / sizeof(uint32_t);
			reply_iphdr->version = 4;
			reply_iphdr->tos = 0;
			reply_iphdr->tot_len = htons(reply_packet.len);
			reply_iphdr->id = 1;
			reply_iphdr->frag_off = 0;
			reply_iphdr->ttl = 64;
			reply_iphdr->protocol = 1;
			reply_iphdr->daddr = ip_hdr->saddr;
			reply_iphdr->saddr = ip_hdr->daddr;
			reply_iphdr->check = 0;
			reply_iphdr->check = ip_checksum(reply_iphdr, sizeof(struct iphdr));

			reply_icmp->type = ICMP_DEST_UNREACH;
			reply_icmp->code = 0;
			reply_icmp->un.echo.id = htons(getpid());
			reply_icmp->checksum = 0;
			reply_icmp->checksum = ip_checksum(reply_icmp, sizeof(struct icmphdr));

			send_packet(reply_packet.interface, &reply_packet);
			
			continue;
		}

		ip_hdr->ttl--;
		ip_hdr->check = 0;	
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		struct arp_entry *rarp = get_arp_entry(ip_hdr->daddr);
		if (rarp == NULL) {
			printf("No ARP entry found!\n");
			continue;
		}

		memcpy(eth_hdr->ether_dhost, rarp->mac, sizeof(rarp->mac) + 1);
		send_packet(rentry->interface, &m);
	}
}

