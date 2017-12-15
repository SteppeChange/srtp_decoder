#pragma once

#include <stdint.h>
#include <vector>
#include <map>
#include <memory>
#include <list>
#include <functional>
#include <iostream>

#include "pcap.h"

#ifdef __linux__ 
#	include <netinet/ip.h>
#	include <arpa/inet.h>
#endif

#define SIZE_ETHERNET 14

// Experimental feature, need to be verified
#define DETECT_ALL_RTP_STREAMS

/* 4 bytes IP address */
struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

/* IPv4 header */
struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification;		// Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
};

#define IP_HL(ip)		(((ip)->ver_ihl) & 0x0f)
#define IP_V(ip)		(((ip)->ver_ihl) >> 4)

#ifndef IPPROTO_UDP
#	define IPPROTO_UDP (17)
#endif
#ifndef IPPROTO_TCP
#	define IPPROTO_TCP (6)
#endif

/* UDP header*/
struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
};

#define UDP_HEADER_SIZE 8

using tcp_seq = uint32_t;
/* TCP Header structure as per RFC 793 */
struct tcp_header
{
	u_short sport;			/* source port */
	u_short dport;			/* destination port */
	tcp_seq seq;			/* sequence number */
	tcp_seq ack;			/* acknowledgement number */
	u_char data_offset;
	u_char flags;
	u_short win;			/* window */
	u_short sum;			/* checksum */
	u_short urp;			/* urgent pointer */
};

#define TH_OFF(th)  (((th)->data_offset & 0xf0) >> 4)

// RTCP Header
struct rtcp_report_hdr {
	unsigned char rc : 5;	/* reception report count */
	unsigned char p : 1;	/* padding flag           */
	unsigned char version : 2; /* protocol version    */
	unsigned char pt;	/* packet type            */
	uint16_t length;	/* length                 */
	uint32_t ssrc;		/* synchronization source */
};

#define RTCP_SR_REPORT (200)
#define RTCP_RR_REPORT (201)
#define RTCP_SDES_REPORT (202)

/* RTP Header*/
struct common_rtp_hdr_t {
	unsigned char cc : 4;	/* CSRC count             */
	unsigned char x : 1;	/* header extension flag  */
	unsigned char p : 1;	/* padding flag           */
	unsigned char version : 2; /* protocol version    */
	unsigned char pt : 7;	/* payload type           */
	unsigned char m : 1;	/* marker bit             */
	uint16_t seq;		/* sequence number        */
	uint32_t ts;		/* timestamp              */
	uint32_t ssrc;		/* synchronization source */
};

/* RTP Header Extension*/
struct common_rtp_hdr_ex_t {
	uint16_t defined_by_profile;
	uint16_t extension_len;
};

/* RTP RFC5285 Header Extension*/
struct rtp_hdr_ex5285_t {
	unsigned char id : 4;
	unsigned char extension_len : 4;
};

/* STUN Message Header */
struct stun_header {
	uint16_t msg_type;
	uint16_t msg_length;
	uint32_t magic_cookie;
	u_char transaction_id[12];
};

/* Turn Message 'ChannelData' Header */
struct channel_data_header {
	uint16_t channel_number;
	uint16_t message_size;
};

#define STUN_CHANNEL_HEADER_SIZE 4
#define STUN_HEADER_SIZE 20
#define STUN_MAGIC_COOKIE 0x2112a442

struct ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
};

#ifndef ETHERTYPE_PUP
#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_NS
#define ETHERTYPE_NS		0x0600
#endif
#ifndef	ETHERTYPE_SPRITE
#define	ETHERTYPE_SPRITE	0x0500
#endif
#ifndef ETHERTYPE_TRAIL
#define ETHERTYPE_TRAIL		0x1000
#endif
#ifndef	ETHERTYPE_MOPDL
#define	ETHERTYPE_MOPDL		0x6001
#endif
#ifndef	ETHERTYPE_MOPRC
#define	ETHERTYPE_MOPRC		0x6002
#endif
#ifndef	ETHERTYPE_DN
#define	ETHERTYPE_DN		0x6003
#endif
#ifndef	ETHERTYPE_LAT
#define	ETHERTYPE_LAT		0x6004
#endif
#ifndef ETHERTYPE_SCA
#define ETHERTYPE_SCA		0x6007
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP	0x8035
#endif
#ifndef	ETHERTYPE_LANBRIDGE
#define	ETHERTYPE_LANBRIDGE	0x8038
#endif
#ifndef	ETHERTYPE_DECDNS
#define	ETHERTYPE_DECDNS	0x803c
#endif
#ifndef	ETHERTYPE_DECDTS
#define	ETHERTYPE_DECDTS	0x803e
#endif
#ifndef	ETHERTYPE_VEXP
#define	ETHERTYPE_VEXP		0x805b
#endif
#ifndef	ETHERTYPE_VPROD
#define	ETHERTYPE_VPROD		0x805c
#endif
#ifndef ETHERTYPE_ATALK
#define ETHERTYPE_ATALK		0x809b
#endif
#ifndef ETHERTYPE_AARP
#define ETHERTYPE_AARP		0x80f3
#endif
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6		0x86dd
#endif
#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q		0x8100
#endif
#ifndef	ETHERTYPE_LOOPBACK
#define	ETHERTYPE_LOOPBACK	0x9000
#endif


typedef std::vector<unsigned char> srtp_packet_t;
typedef std::list<srtp_packet_t> srtp_packets_t;

struct rtp_info
{
	rtp_info(bool audp, uint32_t assrc, unsigned char payload, time_t t, uint32_t seq)
		: udp(audp), ssrc(assrc), pt(payload), first_ts(t), last_ts(t), first_seq(seq), last_seq(seq), packets(1)
	{
	}

	bool udp { true };

	ip_address src_addr;
	uint16_t src_port { 0 };
	ip_address dst_addr;
	uint16_t dst_port { 0 };

	uint32_t ssrc { 0 };
	unsigned char pt { 0 };

	time_t first_ts { 0 };
	time_t last_ts { 0 };

	uint32_t first_seq { 0 };
	uint32_t last_seq { 0 };

	uint32_t packets { 0 };

	srtp_packets_t srtp_stream;
};

// RTP info map with key consists of  src_IP:port + dst_IP:port + SSRC
using streams = std::map<std::string, rtp_info>;

struct global_params
{
    // input parameters
	std::string filter;
	bool verbose {false};
	uint32_t ssrc {0};

    // output parameters
	streams srtp_streams;
};

