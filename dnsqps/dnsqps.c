/*
 * $Id: dnsqps.c,v 0.0725 2013/08/30 17:10:25 Carl Guan Exp $
 * 
 * http://www.baidu.com/
 * 
 * Copyright (c) 2013, The Baidu, Inc.  All rights reserved.  See
 * the LICENSE file for details.
 */


#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netdb.h>

#include <pcap.h>
//#include <pcap/pcap.h>
//#include "pcap-int.h"

#define PCAP_SNAPLEN 65535
#define MAX_QNAME_SZ 512
#define DNS_MSG_HDR_SZ 12
#ifndef ETHER_HDR_LEN
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#endif
#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q 0x8100
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif
#if defined(__linux__) || defined(__GLIBC__) || defined(__GNU__)
#define uh_dport dest
#define uh_sport source
#endif

static const char *Version = "20130830";

char *device = NULL;
pcap_t *pcap = NULL;
char *progname = NULL;
int promisc_flag = 1;
char *bpf_program_str = "udp port 53";
static unsigned short check_port = 0;
unsigned int query_count_intvl = 0;
unsigned int reply_count_intvl = 0;
int opt_count_queries = 0;
int opt_count_replies = 0;

int (*handle_datalink) (const u_char * pkt, int len)= NULL;

typedef struct _rfc1035_header rfc1035_header;
struct _rfc1035_header {
    unsigned short id;
    unsigned int qr:1;
    unsigned int opcode:4;
    unsigned int aa:1;
    unsigned int tc:1;
    unsigned int rd:1;
    unsigned int ra:1;
    unsigned int rcode:4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

int
handle_dns(const char *buf, int len)
{
    rfc1035_header qh;
    unsigned short us;

    if (len < sizeof(qh))
	return 0;

    memcpy(&us, buf + 00, 2);
    qh.id = ntohs(us);

    memcpy(&us, buf + 2, 2);
    us = ntohs(us);
    qh.qr = (us >> 15) & 0x01;
	
    if (0 == qh.qr && 0 == opt_count_queries)
	return 0;
    if (1 == qh.qr && 0 == opt_count_replies)
	return 0;

    if (0 == qh.qr) {
	query_count_intvl++;
    } else {
	reply_count_intvl++;
    }
    return 1;
}

int
handle_udp(const struct udphdr *udp, int len)
{
    if (check_port && check_port != udp->uh_dport && check_port != udp->uh_sport)
	return 0;
    if (0 == handle_dns((char *)(udp + 1), len - sizeof(*udp)))
	return 0;
    return 1;
}

int
handle_ipv4(const struct ip *ip, int len)
{
    int offset = ip->ip_hl << 2;
    if (IPPROTO_UDP != ip->ip_p)
	return 0;
	
    if (0 == handle_udp((struct udphdr *)((char *)ip + offset), len - offset))
	return 0;
    return 1;
}


int
handle_ip(const u_char * pkt, int len, unsigned short etype)
{
    if (ETHERTYPE_IP == etype) {
	return handle_ipv4((struct ip *)pkt, len);
    }
    return 0;
}

int
handle_ether(const u_char * pkt, int len)
{
    struct ether_header *e = (void *)pkt;
    unsigned short etype = ntohs(e->ether_type);
    if (len < ETHER_HDR_LEN)
	return 0;
    pkt += ETHER_HDR_LEN;
    len -= ETHER_HDR_LEN;
    if (ETHERTYPE_8021Q == etype) {
	etype = ntohs(*(unsigned short *)(pkt + 2));
	pkt += 4;
	len -= 4;
    }
    return handle_ip(pkt, len, etype);
}

void
handle_pcap(u_char * udata, const struct pcap_pkthdr *hdr, const u_char * pkt)
{
    if (hdr->caplen < ETHER_HDR_LEN)
	return;
    if (0 == handle_datalink(pkt, hdr->caplen))
	return;
}

/*int
pcap_select(pcap_t * p, int sec, int usec)
{
    fd_set R;
    struct timeval to;
    FD_ZERO(&R);
    FD_SET(pcap_fileno(p), &R);
    to.tv_sec = sec;
    to.tv_usec = usec;
    return select(pcap_fileno(p) + 1, &R, NULL, NULL, &to);
}*/

void prompt_info(int signo)
{
    if(1 == opt_count_queries && 0 == opt_count_replies)
    {
	printf("%d qps\n", query_count_intvl);
    }
    else if(0 == opt_count_queries && 1 == opt_count_replies)
    {
	printf("%d rps\n", reply_count_intvl);
    }
    else
    {
        printf("%d qps\n", query_count_intvl);
	printf("%d rps\n", reply_count_intvl);
    }
    
    pcap_close(pcap);
	exit(0);	
}

void init_sigaction(void)
{
    struct sigaction tact;
    tact.sa_handler = prompt_info;
    tact.sa_flags = 0;
    sigaction(SIGALRM, &tact, NULL);
}

void init_time(void)
{
    struct itimerval value;
    value.it_value.tv_sec = 1;
    value.it_value.tv_usec = 100000;
    value.it_interval = value.it_value;
    setitimer(ITIMER_REAL, &value, NULL);
}


void
usage(void)
{
    fprintf(stderr, "usage: %s [opts] netdevice\n", progname);
    fprintf(stderr, "\t-Q\tCount queries\n");
    fprintf(stderr, "\t-R\tCount responses\n");
    fprintf(stderr, "\t-v\tshow version information\n");
    fprintf(stderr, "\t-h\tshow help information\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int x;
    struct bpf_program fp;

    progname = strdup(strrchr(argv[0], '/') ? strchr(argv[0], '/') + 1 : argv[0]);

    while ((x = getopt(argc, argv, "hQRv")) != -1) {
	switch (x) {
	case 'Q':
	    opt_count_queries = 1;
	    break;
	case 'R':
	    opt_count_replies = 1;
	    break;
	case 'v':
	    fprintf(stderr, "dnsqps Version: %s\n", Version);
	    fprintf(stderr, "http://www.baidu.com/\n");
	    exit(0);
	case 'h':
	    usage();
	default:
	    usage();
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if (argc < 1)
	usage();
    device = strdup(argv[0]);
	
    if (!strstr(bpf_program_str, "port "))
    	check_port = htons(53);
    if (0 == opt_count_queries && 0 == opt_count_replies)
	opt_count_queries = 1;

    pcap = pcap_open_live(device, PCAP_SNAPLEN, promisc_flag, 1000, errbuf);

    if (NULL == pcap) {
	fprintf(stderr, "pcap_open_*: %s\n", errbuf);
	exit(1);
    }

    memset(&fp, '\0', sizeof(fp));
    x = pcap_compile(pcap, &fp, bpf_program_str, 1, 0);
    if (x < 0) {
	fprintf(stderr, "pcap_compile failed\n");
	exit(1);
    }
    x = pcap_setfilter(pcap, &fp);
    if (x < 0) {
	fprintf(stderr, "pcap_setfilter failed\n");
	exit(1);
    }
//    pcap_setnonblock(pcap, 1, errbuf);

    switch (pcap_datalink(pcap)) {
    case DLT_EN10MB:
	handle_datalink = handle_ether;
	break;
    default:
	fprintf(stderr, "unsupported data link type %d\n",
	pcap_datalink(pcap));
	return 1;
	break;
    }
	
//    pcap_select(pcap, 1, 0);
//    pcap_dispatch(pcap, -1, handle_pcap, NULL);
    init_time();
    init_sigaction();
    pcap_loop(pcap, 0, handle_pcap, NULL);

    return 0;
}
