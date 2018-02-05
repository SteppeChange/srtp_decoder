#include <cassert>
#include <utility>
#include <string>

#include "pcap_reader.h"

#ifdef __APPLE__
// http://fuckingclangwarnings.com
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wformat-security"
#endif
template<typename... Args>
void verbose(bool verbose, Args&&... args)
{
	if (verbose)
		printf(std::forward<Args&&>(args)...);
}
#ifdef __APPLE__
# pragma clang diagnostic pop
#endif

// function returns ssrc if found rtp packet
static int parse_rtp(global_params *params, time_t ts, ip_header const *ih, char *rtp_body, int rtp_size);

inline static bool is_ip_over_eth(const u_char* packet)
{
    return ntohs(((struct ether_header *)packet)->ether_type) == ETHERTYPE_IP;
}

// http://www4.ncsu.edu/~mlsichit/Teaching/407/Resources/udpChecksum.html
static uint16_t sc_csum_partial(global_params *params, uint16_t *data, uint16_t count)
{
    uint32_t sum = 0;
    uint16_t size = count >> 1;
    for (uint16_t i = 0; i < size; ++i) {
	sum += *data++;
	//verbose(params->verbose, "sc_csum_partial[%02d]: 0x%x\n", i, sum);
    }
    if (count & 0x1) {
	sum += *(uint8_t *)data;
	//verbose(params->verbose, "sc_csum_partial[%02d]: 0x%x\n", count, sum);
    }
    while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);
    //verbose(params->verbose, "sc_csum_partial: 0x%x\n", sum);
    return sum;
}

static uint16_t sc_csum_tcpudp_magic(global_params *params, const ip_address *ip_saddr, const ip_address *ip_daddr, uint16_t proto, uint16_t len, uint16_t checksum, uint16_t crc)
{
    uint32_t sum = 0;

    const uint16_t *ptr = (const uint16_t *)ip_saddr;
    sum += *ptr++;
    sum += *ptr;
    //verbose(params->verbose, "sc_csum_tcpudp_magic+ip_src: 0x%x\n", sum);

    ptr = (const uint16_t *)ip_daddr;
    sum += *ptr++;
    sum += *ptr;
    //verbose(params->verbose, "sc_csum_tcpudp_magic+ip_dst: 0x%x\n", sum);

    sum += htons(len);
    //verbose(params->verbose, "sc_csum_tcpudp_magic+len: 0x%x\n", sum);

    sum += htons(proto);
    //verbose(params->verbose, "sc_csum_tcpudp_magic+proto: 0x%x\n", sum);

    sum += checksum;
    //verbose(params->verbose, "sc_csum_tcpudp_magic+checksum: 0x%x\n", sum);

    sum -= crc;
    //verbose(params->verbose, "sc_csum_tcpudp_magic-crc: 0x%x\n", sum);

    while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);
    //verbose(params->verbose, "sc_csum_tcpudp_magic: 0x%x\n", sum);

    return ~sum;
}

/* Callback function invoked by libpcap for every incoming packet */
void p_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	global_params *params = reinterpret_cast<global_params*>(param);

	static int pack_no{ 0 };
	struct tm *ltime;
	char timestr[16];

	const ip_header  *ih = NULL;
	const udp_header *uh = NULL;
	const tcp_header *th = NULL;
	const char *sh = NULL;

	u_int eth_hdr_size;
	u_int ip_hdr_size;
	u_int tcp_hdr_size;

	u_int tcp_data_size = 0;
	u_int udp_size = 0;
	u_int data_size = 0;

	uint16_t recv_crc = 0;
	uint16_t calc_crc = 0;

	/* unused parameter */
	(void)(param);

	++pack_no;

	/* convert the timestamp to readable format */
	time_t const ts = header->ts.tv_sec;
	ltime = localtime(&ts);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	eth_hdr_size = is_ip_over_eth(pkt_data) ? SIZE_ETHERNET : 0;

	/* retrieve the position of the ip header */
	ih = (ip_header *)(pkt_data + eth_hdr_size);
	ip_hdr_size = IP_HL(ih) * 4;

	/* determine protocol */
	switch(ih->proto) {
	case IPPROTO_UDP:
		/* retrieve the position of the udp header */
		uh = (udp_header *)((u_char*)ih + ip_hdr_size);
		/* print ip addresses and udp ports */
		verbose(params->verbose, "[%d] UDP: %s.%.6d\t%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d length:%d\n",
			pack_no, timestr, header->ts.tv_usec,
			ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ntohs(uh->sport),
			ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ntohs(uh->dport),
			header->len);
		udp_size = ntohs(uh->len);	// udp_size = header_size(8) + data_size
		sh = (char *)uh + UDP_HEADER_SIZE;
		data_size = udp_size - UDP_HEADER_SIZE;

		recv_crc = ntohs(uh->crc);
		calc_crc = ntohs(sc_csum_tcpudp_magic(params, &ih->saddr, &ih->daddr, ih->proto, udp_size,
                                                      sc_csum_partial(params, (uint16_t *)uh, udp_size), uh->crc));

		verbose(params->verbose, "size: eth: %d, ip: %d, udp: %d, data_len: %d, orig_crc: 0x%x, calc_crc: 0x%x\n",
			eth_hdr_size, ip_hdr_size, UDP_HEADER_SIZE, data_size, recv_crc, calc_crc);
		if (recv_crc != calc_crc)
			verbose(params->verbose, "UDP CHECKSUM IS INCONSISTENT!\n");
		break;

	case IPPROTO_TCP:
		/* retrieve the position of the tcp header */
		th = (tcp_header *)((u_char*)ih + ip_hdr_size);
		/* print ip addresses and tcp ports */
		verbose(params->verbose, "[%d] TCP: %s.%.6d\t%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d length:%d\n",
			pack_no, timestr, header->ts.tv_usec,
			ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ntohs(th->sport),
			ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ntohs(th->dport),
			header->len);
		tcp_hdr_size = TH_OFF(th) * 4;
		tcp_data_size = header->len - (eth_hdr_size + ip_hdr_size + tcp_hdr_size);
		sh = (char *)th + tcp_hdr_size;
		data_size = tcp_data_size;
		verbose(params->verbose, "size: eth: %d, ip: %d, tcp: %d, data: %d\n", eth_hdr_size, ip_hdr_size, tcp_hdr_size, data_size);
		break;

	default:
		return;
	}

	assert(sh);

	char *rtp_body = 0;
	u_int rtp_size = 0;

	// Packet can be:
	// 1. UDP (moves only one voice fragment)
	// 1.1. ChannelData TURN (ChannelMask == 0x40xx) with RTP inside (1)
	// 1.2. Another TURN-message (2)
	// 1.3. RTP (3)
	// 1.4. Something else (4)
	// 2. TCP (several PDUs may be inside) with one or several PDUs
	// 2.1. PDU is ChannelData TURN (ChannelMask == 0x40xx) with RTP inside (5)
	// 2.2. PDU is another TURN-message (6)
	// 2.4. PDU is something else (7)
	for (;data_size > STUN_CHANNEL_HEADER_SIZE; data_size -= (rtp_size + STUN_CHANNEL_HEADER_SIZE), sh += (rtp_size + STUN_CHANNEL_HEADER_SIZE))
	{
		verbose(params->verbose, "data size: %d\n", udp_size ? udp_size : data_size);

		auto stun_hdr = reinterpret_cast<const channel_data_header *>(sh);
		auto channel_mask = static_cast<uint8_t>(stun_hdr->channel_number);
		auto magic_cookie = htonl(*(reinterpret_cast<uint32_t *>((char *)sh + STUN_CHANNEL_HEADER_SIZE)));

		if (channel_mask & 0x40) {
			// (1), (5)
			rtp_size = htons(stun_hdr->message_size);
			rtp_body = (char *)sh + STUN_CHANNEL_HEADER_SIZE;

			// check amount of stun data
			if (tcp_data_size && data_size < rtp_size + STUN_CHANNEL_HEADER_SIZE) {
				verbose(params->verbose, "stun: not enough data or not stun, skip packet\n");
				break;
			}

			parse_rtp(params, ts, ih, rtp_body, rtp_size);
			//A.D. FIX: data is aligned, so we need make rtp_size to be multiple 4
			if (tcp_data_size && (rtp_size & 0x0003)) {
				rtp_size = ((rtp_size >> 2) + 1) << 2;
			}
		} else if (magic_cookie == STUN_MAGIC_COOKIE) {
			// (2), (6)
			rtp_body = (char *)sh + STUN_CHANNEL_HEADER_SIZE;
			rtp_size += (STUN_HEADER_SIZE - STUN_CHANNEL_HEADER_SIZE);

			verbose(params->verbose, "stun: message %d bytes skipped\n", htons(stun_hdr->message_size));
			// UDP moves only one user message
			if (udp_size)
				break;
		} else if (udp_size) {
			// (3)
			rtp_size = udp_size - UDP_HEADER_SIZE;
			rtp_body = (char*)uh + UDP_HEADER_SIZE;

			parse_rtp(params, ts, ih, rtp_body, rtp_size);
			break;
		} else {
			// (4), (7)
			verbose(params->verbose, "unknown: message skipped\n");
			break;
		}
	}
	verbose(params->verbose, "\n");
}

std::string ip_to_string(const ip_address &ip)
{
	std::string s;
	s += std::to_string(ip.byte1).append(".");
	s += std::to_string(ip.byte2).append(".");
	s += std::to_string(ip.byte3).append(".");
	s += std::to_string(ip.byte4);
	return s;
};

static void parse_rtcp_rb(global_params *params, uint32_t *rtcp_rb)
{
    uint32_t ssrc = ntohl(*rtcp_rb++);
    uint32_t last_pack_lost = *rtcp_rb & 0xff;
    uint32_t cum_pack_lost = (*rtcp_rb++ & 0xffffff00) >> 8;
    verbose(params->verbose, "RTCP Report Block:\n\tssrc=0x%x\n\tlost=%d\n\tcumulative_lost=%u\n",
        ssrc, last_pack_lost, cum_pack_lost);
}

int parse_rtp(global_params *params, time_t ts, ip_header const *ih, char *rtp_body, int rtp_size)
{
        auto ip_hdr_size = IP_HL(ih) * 4;

        auto hdr = reinterpret_cast<common_rtp_hdr_t const *>(rtp_body);
	auto rtcp_hdr = reinterpret_cast<rtcp_report_hdr const *>(rtp_body);

	auto src_addr = ih->saddr;
	auto dst_addr = ih->daddr;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;

	if (ih->proto == IPPROTO_UDP) {
		udp_header *uh = (udp_header *)((u_char*)ih + ip_hdr_size);
		src_port = htons(uh->sport);
		dst_port = htons(uh->dport);
	} else if (ih->proto == IPPROTO_TCP) {
		tcp_header *th = (tcp_header *)((u_char*)ih + ip_hdr_size);
		src_port = htons(th->sport);
		dst_port = htons(th->dport);
	} else {
		assert(false);
		return 0;
	}

	std::string key;
	key += ip_to_string(src_addr);
	key += ":";
	key += std::to_string(src_port);
	key += ":";
	key += ip_to_string(dst_addr);
	key += ":";
	key += std::to_string(dst_port);
	key += ":";

	//TODO: there are many of non-RTP protocols, it isn't enough to detect RTP by version only
	if (hdr->version != 2) {
		verbose(params->verbose, "unknown (non-rtp), size: %d\n", rtp_size);
		return 0;
	}
#define RTCP_COMMON_PART 8
	if (rtcp_hdr->pt == RTCP_SR_REPORT) {
		uint16_t rtcp_size = ntohs(rtcp_hdr->length);
		uint32_t *rtcp_ptr = (uint32_t *)(rtp_body + RTCP_COMMON_PART);
		uint32_t ntp_sec = ntohl(*rtcp_ptr++);
		uint32_t ntp_usec = ntohl(*rtcp_ptr++);
		uint32_t rtp_ts = ntohl(*rtcp_ptr++);
		uint32_t pack_cnt = ntohl(*rtcp_ptr++);
		uint32_t octet_cnt = ntohl(*rtcp_ptr++);

		verbose(params->verbose, "RTCP Sender Report: ssrc=0x%x, rc=%d, words=%d\n",
		    ntohl(rtcp_hdr->ssrc), rtcp_hdr->rc, rtcp_size);
		verbose(params->verbose, "\tssrc=0x%x\n\tntp_ts=%u.%u\n\trtp_ts=%u\n\tpack=%u\n\toctet=%u\n",
		    ntohl(rtcp_hdr->ssrc), ntp_sec, ntp_usec, rtp_ts, pack_cnt, octet_cnt);
		for (int i = 1; i <= rtcp_hdr->rc; ++i, rtcp_ptr += 6)
		    parse_rtcp_rb(params, rtcp_ptr);
		return 0;
	}
	if (rtcp_hdr->pt == RTCP_RR_REPORT) {
		uint16_t rtcp_size = ntohs(rtcp_hdr->length);
		uint32_t *rtcp_ptr = (uint32_t *)(rtp_body + RTCP_COMMON_PART);

		verbose(params->verbose, "RTCP Receiver Report: ssrc=0x%x, rc=%d, words=%d\n",
		    ntohl(rtcp_hdr->ssrc), rtcp_hdr->rc, rtcp_size);
		for (int i = 1; i <= rtcp_hdr->rc; ++i, rtcp_ptr += 6)
		    parse_rtcp_rb(params, rtcp_ptr);
		return 0;
	}
	verbose(params->verbose, "rtp: head, size: %d\n", rtp_size);

	auto ssrc = ntohl(hdr->ssrc);
	key += std::to_string(ssrc);

        auto seq = htons(hdr->seq);

    verbose(params->verbose, "\tversion=%d\n\tpad=%d\n\text=%d\n\tcc=%d\n\tpt=%d\n\tm=%d\n\tseq=%d\n\tts=%u\n\tssrc=0x%x\n",
            hdr->version, hdr->p, hdr->x, hdr->cc, hdr->pt, hdr->m, htons(hdr->seq), htonl(hdr->ts), htonl(hdr->ssrc));

    if (!params->ssrc || (params->ssrc && params->ssrc == ssrc)) {
        streams::iterator itr = params->srtp_streams.find(key);
        if (itr == params->srtp_streams.end()) {
            params->srtp_streams.insert(streams::value_type(key,
                                                            rtp_info(ih->proto == IPPROTO_UDP, ssrc, hdr->pt, ts, seq)));

            itr = params->srtp_streams.find(key);
            itr->second.src_addr = src_addr;
            itr->second.dst_addr = dst_addr;
            itr->second.src_port = src_port;
            itr->second.dst_port = dst_port;
        } else {
            if (seq != itr->second.last_seq+1) {
                if (seq < itr->second.last_seq) {
                    //both TCP and UDP cases
                    if (!hdr->m) {
                        //not first packet after re-ICE-establishing
                        verbose(params->verbose, "rtp: reordered or retransmitted packet detected: %d, skip\n", seq);
                        return 0;
                    }
                } else if (seq == itr->second.last_seq) {
                    //UDP only case
                    verbose(params->verbose, "rtp: copy of packet detected: %d, skip\n", seq);
                    return 0;
                } else {
                    //UDP only case
                    verbose(params->verbose, "rtp: lost packet(s) detected: %d - %d\n", itr->second.last_seq+1, seq);
                }
            }

            itr->second.last_ts = ts;
            itr->second.last_seq = seq;

            ++itr->second.packets;
        }

        if (params->ssrc && params->ssrc == ssrc) {
            srtp_packet_t srtp_packet(rtp_body, rtp_body + rtp_size);
            itr->second.srtp_stream.push_back(srtp_packet);
        }
    }

	return ssrc;
}

bool read_pcap(std::string const& file, global_params& params)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;

	/* Open the capture file */
	if ((fp = pcap_open_offline(file.c_str(), errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s: %s\n", file.c_str(), errbuf);
		return false;
	}

	std::string packet_filter = params.filter.empty() ? "udp or tcp" : params.filter;
	u_int netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(fp, &fcode, packet_filter.c_str(), 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_close(fp);
		return  false;
	}

	//set the filter
	if (pcap_setfilter(fp, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_close(fp);
		return  false;
	}

	//work
	pcap_loop(fp, 0, &p_handler, (u_char*)(&params));

	pcap_close(fp);
	return true;
}

