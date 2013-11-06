 /*
 *$Id: dnsqps.c,v 0.0725 2013/08/30 17:10:25 Carl Guan Exp $
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
#include <netinet/tcp.h>
#include <netdb.h>

#include <pcap.h>

// thanks to dnstop's authors
#include "inX_addr.h" 

#define PCAP_SNAPLEN 65535
#define MAX_QNAME_SZ 512
#define DNS_MSG_HDR_SZ 12
#define MAX_BUF 128
#define MAX_NUM 8
#define IPPROTO_UDP_TTM 193

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

static const char *Version = "201300918";

char *device = NULL;
pcap_t *pcap = NULL;
char *progname = NULL;
int promisc_flag = 1;
char *bpf_program_str = "port 53";
static unsigned short check_port = 0;
unsigned int query_count_intvl = 0;
unsigned int reply_count_intvl = 0;
int opt_count_queries = 0;
int opt_count_replies = 0;
int dst_flag = 0;
int ttm_flag = 0;

int (*handle_datalink) (const u_char * pkt, int len)= NULL;
void (*qr_count) (unsigned int qr_flag, const inX_addr *dst_addr) = NULL;
int (*handle_ip_misc) (const struct ip *ip, int len) = NULL;

typedef struct _rfc1035_header {
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
} rfc1035_header;

typedef struct ip_list_d {
    inX_addr addr;
    void *data;
    struct ip_list_d *next;
} ip_list_t;

ip_list_t *Attachlist = NULL;

void
ssplit(char *line, char *p[], char *delim)
{
    char *buf = line;
    char *outer_ptr = NULL;
    char *inner_ptr = NULL;
    int in = 0;

    while ((p[in]=strtok_r(buf, delim, &outer_ptr))!= NULL)
    {
        buf = p[in];
        while ((p[in] = strtok_r(buf, delim, &inner_ptr)) != NULL)
        {
            in++;
            buf=NULL;
        }
        buf=NULL;
    }
}

int
attach_list_match(const inX_addr *addr)
{
    ip_list_t *ptr;
    
    for (ptr = Attachlist; ptr != NULL; ptr = ptr->next){
	if (0 == inXaddr_cmp(addr, &ptr->addr))
	    return 0;
    }
    return 1;
}

void
attach_list_add(const inX_addr *addr)
{
    ip_list_t *new;
    if (attach_list_match(addr) == 0)
	return;
    
    new = malloc(sizeof(ip_list_t));
    if (new == NULL){
	perror("malloc");
	return;
    }
    
    new->addr = *addr;
    new->next = Attachlist;
    Attachlist = new;
}

void
attach_dst_addr(const char *name)
{
    struct addrinfo *ai_list;
    struct addrinfo *ai_ptr;
    struct inX_addr *addr;
    char ip[MAX_BUF];
    char *seg[MAX_NUM];
    char **ips;
    int status;
    
    strcpy(ip, name);
    ssplit(ip, seg, " ");
    
    for(ips = seg; *ips != NULL; ips++){
	status = getaddrinfo(*ips, NULL, NULL, &ai_list);
	if (status != 0 )
	    return ;
    
	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next){
	    if (ai_ptr->ai_family == AF_INET){
	        inXaddr_assign_v4(&addr, &((struct sockaddr_in *)ai_ptr->ai_addr)->sin_addr);
	        attach_list_add(&addr);
	    }
	}
    
	freeaddrinfo(ai_list);
    }
}

void std_qr_count(unsigned int qr_flag, const inX_addr *dst_addr){
    if (0 == qr_flag){
        query_count_intvl++;
    } else {
        reply_count_intvl++;
    }

}

void dst_qr_count(unsigned int qr_flag, const inX_addr *dst_addr){
    if (0 == qr_flag && 0 == attach_list_match(dst_addr)) {
        query_count_intvl++;
    }else{
        reply_count_intvl++;
    }

}

int
handle_dns(const char *buf, int len, const inX_addr *dst_addr)
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

    qr_count(qh.qr, dst_addr);

    return 1;
}

int
handle_tcp(const struct tcphdr *tcp, int len, const inX_addr *dst_addr)
{
    
/*
struct tcphdr {
        __be16  source;
        __be16  dest;
        __be32  seq;
        __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u16   res1:4,
                doff:4,
                fin:1,
                syn:1,
                rst:1,
                psh:1,
                ack:1,
                urg:1,
                ece:1,
                cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
        __u16   doff:4,
                res1:4,
                cwr:1,
                ece:1,
                urg:1,
                ack:1,
                psh:1,
                rst:1,
                syn:1,
                fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif  
        __be16  window;
        __sum16 check;
        __be16  urg_ptr;
}   
*/
    
    if (check_port && check_port != tcp->dest && check_port != tcp->source)
	return 0;
    
    if (0 == tcp->psh)
        return 0;
    
    if (0 ==  handle_dns((char *)(tcp + (tcp->doff*4 - 20) + 3), len - sizeof(*tcp) - (tcp->doff*4 - 20), dst_addr))
	return 0;
    return 1;
}

int
handle_udp(const struct udphdr *udp, int len, const inX_addr *dst_addr)
{
    if (check_port && check_port != udp->uh_dport && check_port != udp->uh_sport)
	return 0;
    if (0 == handle_dns((char *)(udp + 1), len - sizeof(*udp), dst_addr))
	return 0;
    return 1;
}

int
handle_ipv4(const struct ip *ip, int len)
{
    int offset = ip->ip_hl << 2;
    inX_addr dst_addr;
    
    inXaddr_assign_v4(&dst_addr, &ip->ip_dst);
    
    if (IPPROTO_UDP == ip->ip_p || IPPROTO_UDP_TTM == ip->ip_p)
    {
	if (0 == handle_udp((struct udphdr *)((char *)ip + offset), len - offset, &dst_addr))
	    return 0;
	return 1;
    }
    else if (IPPROTO_TCP == ip->ip_p)
    {
	if (0 == handle_tcp((struct tcphdr *)((char *)ip + offset), len - offset, &dst_addr))
	    return 0;
	return 1;
    }
    else
    {
	return 1;
    }
    
}

int
handle_ipv4_ttm(const struct ip *ip, int len)
{
    int offset = (ip->ip_hl << 2) + 8;
    inX_addr dst_addr;
    
    inXaddr_assign_v4(&dst_addr, &ip->ip_dst);
    
    if (IPPROTO_UDP == ip->ip_p || IPPROTO_UDP_TTM == ip->ip_p)
    {
	if (0 == handle_udp((struct udphdr *)((char *)ip + offset), len - offset, &dst_addr))
	    return 0;
	return 1;
    }
    else if (IPPROTO_TCP == ip->ip_p)
    {
	if (0 == handle_tcp((struct tcphdr *)((char *)ip + offset), len - offset, &dst_addr))
	    return 0;
	return 1;
    }
    else
    {
	return 1;
    }
    
}

int
handle_ip(const u_char * pkt, int len, unsigned short etype)
{
    if (ETHERTYPE_IP == etype) {
	return handle_ip_misc((struct ip *)pkt, len);
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

void
prompt_info(int signo)
{
    ip_list_t *tmp = NULL;
    
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
    
    for (tmp = Attachlist; tmp != NULL; tmp = Attachlist){
	Attachlist = Attachlist->next;
	free(tmp);
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
    value.it_value.tv_usec = 1000;
    value.it_interval = value.it_value;
    setitimer(ITIMER_REAL, &value, NULL);
}


void
usage(void)
{
    fprintf(stderr, "usage: %s [opts] [-d 'ip1 {ip2 ... }']  netdevice\n", progname);
    fprintf(stderr, "\t-Q\tCount queries\n");
    fprintf(stderr, "\t-R\tCount responses\n");
    fprintf(stderr, "\t-d\tCapture Destination IP Address (multi ip must use ' ' to split)\n");
    fprintf(stderr, "\t-t\tenable ttm module suport\n");
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

    while ((x = getopt(argc, argv, "hd:QRtv")) != -1) {
	switch (x) {
	case 'Q':
	    opt_count_queries = 1;
	    break;
	case 'R':
	    opt_count_replies = 1;
	    break;
	case 'd':
	    dst_flag = 1;
	    attach_dst_addr(optarg);
	    break;
	case 'v':
	    fprintf(stderr, "dnsqps Version: %s\n", Version);
	    fprintf(stderr, "http://www.baidu.com/\n");
	    exit(0);
	case 'h':
	    usage();
	case 't':
	    ttm_flag = 1;
	    break;
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

    if (1 == dst_flag){
	qr_count = dst_qr_count;
    }else{
	qr_count = std_qr_count;
    }
    
    if (1 == ttm_flag){
	handle_ip_misc = handle_ipv4_ttm;
    }else{
	handle_ip_misc = handle_ipv4;
    }
    
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

    init_time();
    init_sigaction();
    pcap_loop(pcap, 0, handle_pcap, NULL);

    return 0;
}
