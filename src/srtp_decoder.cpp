// srtp_decoder.cpp : Defines the entry point for the console application.
//

#include "srtp_decoder.h"
#include "decoder.h"
#include "base64.h"
#include "pcap.h"

#include <string>
#include <iostream>
#include <cassert>

#include "docopt/docopt.h"
#include "pcap_reader.h"

// example key_params: "YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2"
static bool ParseKeyParams(const std::string& key_params, uint8_t* key, int len)
{
	// Fail if base64 decode fails, or the key is the wrong size.
	std::string key_b64(key_params), key_str;
	if (!Base64::Decode(key_b64, Base64::DO_STRICT, &key_str, NULL) ||
			static_cast<int>(key_str.size()) != len) {
		std::cerr << "ERROR: Bad master key encoding, can't unbase64" << std::endl;
		throw std::runtime_error("SRTP fails");
	}
	memcpy(key, key_str.c_str(), len);
	return true;
}

static int SrtpCryptoSuiteFromName(const std::string& crypto_suite)
{
	if (crypto_suite == CS_AES_CM_128_HMAC_SHA1_32)
		return SRTP_AES128_CM_SHA1_32;
	if (crypto_suite == CS_AES_CM_128_HMAC_SHA1_80)
		return SRTP_AES128_CM_SHA1_80;
	return SRTP_INVALID_CRYPTO_SUITE;
}

static void int_to_char(unsigned int i, unsigned char ch[4])
{
	ch[0] = i >> 24;
	ch[1] = (i >> 16) & 0xFF;
	ch[2] = (i >> 8) & 0xFF;
	ch[3] = i & 0xFF;
}

static const char USAGE[] =
R"(srtp_decoder

    Usage:
        srtp_decoder [-v] -f <input_tcpdump_pcap_path> -o <output_decoded_payload_path> -s <ssrc_into_rtp_hex_format> -k <base64_secret_key> -r <sha_crypto_suite> -c <container> [-e <pcap_filter_expression>]
        srtp_decoder [-v] -l -f <input_tcpdump_pcap_path> [-s <ssrc_into_rtp_hex_format> -e <pcap_filter_expression>]
        srtp_decoder (-h | --help)
        srtp_decoder --version

    Options:
        -f --file       Input ".pcap" file path (TCPDump format only, not WireShark ".pcapng"!).
        -o --output     Output ".payload" file path.
        -s --ssrc       RTP stream identifier into hex format.
        -k --key        Server's secret string (base64).
        -r --crypto     sha_crypto_suite symbolic name ("AES_CM_128_HMAC_SHA1_80", etc..).
        -c --container  To store opus, you need some kind of container ("true/false") that stores the packet boundaries.
        -e --expression Pcap filter expression, "tcp or udp" etc.
        -l --list       Produce all rtp streams information into ".csv" file.
        -v --verbose    Verbose output.
        -h --help       Show this screen.
        --version       Show version.

    Examples:
        srtp_decoder -f ./tests/pcma.pcap -o ./tests/pcma.payload -s 0xdeadbeef -k aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz -r AES_CM_128_HMAC_SHA1_80 -c false
        srtp_decoder -f ./tests/webrtc_opus_p2p.pcap -o ./tests/output/webrtc_opus_p2p.payload -s 0x20C23467 -k FfLxRxclZ/lNM/g5MNSZgmvAUzR/pgSIVyOHUHji -r AES_CM_128_HMAC_SHA1_80 -c true
)";

int main(int argc, char* argv[])
{
	std::map<std::string, docopt::value> args = docopt::docopt(USAGE, { argv + 1, argv + argc }, true, VERSION);
#ifdef _DEBUG
	for (auto const& arg : args) {
		std::cout << arg.first << ": " << arg.second << std::endl;
	}
	std::cout << std::endl;
#endif
	global_params params;
	params.filter = "udp or tcp";

	bool show_all_streams_info = false;

	auto get_arg = [&args](const char *name) {
		if (args[name] && args[name].isString())
			return args[name].asString();
		return std::string("");
	};

	std::string input_path = get_arg("<input_tcpdump_pcap_path>");
	std::string output_path = get_arg("<output_decoded_payload_path>");
	std::string ssrc_str = get_arg("<ssrc_into_rtp_hex_format>");
	params.ssrc = (uint32_t)(strtoul(ssrc_str.c_str(), 0, 16) & 0xFFFFFFFF);
	std::string keyBase64 = get_arg("<base64_secret_key>");
	std::string sha = get_arg("<sha_crypto_suite>");
	bool container = false;
	if (args["--container"] && args["<container>"].isString())
		container = args["<container>"].asString() == std::string("true");
	if (args["--expression"] && args["--expression"].isString())
		params.filter = args["--expression"].asString();
	if (args["--list"] && args["--list"].isBool())
		show_all_streams_info = args["--list"].asBool();
	params.verbose = args["--verbose"].asBool();

	std::cout << "input pcap file: " << input_path << std::endl;
	std::cout << "output payload file: " << output_path << std::endl;
	std::cout << "32-bit SSRC identifier: 0x" << std::hex << params.ssrc << std::dec << std::endl;
	std::cout << "AES Base64 crypto key: " << keyBase64 << std::endl;
	std::cout << "crypto-suite: " << sha << std::endl;
	std::cout << "payload packaging: " << (container ? "true" : "false") << std::endl;
	std::cout << "pcap filter expression: " << params.filter << std::endl;
	std::cout << std::endl;

	try {
		if (!read_pcap(input_path, params)) {
			return 1;
		}
		if (show_all_streams_info) {
			// produce CSV-file
			std::string csv_path = input_path;
			auto pos = csv_path.find_last_of('.');
			if (pos != csv_path.npos) {
				csv_path.replace(pos+1, csv_path.npos, "csv");
			} else {
				csv_path.append(".csv");
			}
			do {
				FILE *csv_file = fopen(csv_path.c_str(), "wt");
				if (!csv_file) {
					std::cerr << "Can't open file: " << csv_path << std::endl;
					break;
				}
				fprintf(csv_file, "begin_timestamp,end_timestamp,ssrc,src_addr,dest_addr,proto,rtp_type,begin_seq,end_seq,packets\n");
				if (params.verbose)
					std::cout << "=== RTP STREAMS INFO ===" << std::endl;
				for (auto &ri : params.srtp_streams) {
					if (ri.second.packets < 2)
						continue;
#ifdef WIN32
					fprintf(csv_file, "%llu,%llu,0x%x,%d.%d.%d.%d:%d,%d.%d.%d.%d:%d,%s,%d,%d,%d,%d\n",
#else
					fprintf(csv_file, "%lu,%lu,0x%x,%d.%d.%d.%d:%d,%d.%d.%d.%d:%d,%s,%d,%d,%d,%d\n",
#endif
						ri.second.first_ts, ri.second.last_ts, ri.second.ssrc,
						ri.second.src_addr.byte1, ri.second.src_addr.byte2, ri.second.src_addr.byte3, ri.second.src_addr.byte4, ri.second.src_port,
						ri.second.dst_addr.byte1, ri.second.dst_addr.byte2, ri.second.dst_addr.byte3, ri.second.dst_addr.byte4, ri.second.dst_port,
						ri.second.udp ? "udp" : "tcp", ri.second.pt, ri.second.first_seq, ri.second.last_seq, ri.second.packets);

					if (params.verbose) {
#ifdef WIN32
						printf("Found %06d RTP packets: ssrc: 0x%x, begin_ts: %llu, end_ts: %llu, begin_seq: %d, end_seq: %d\n",
#else
						printf("Found %06d RTP packets: ssrc: 0x%x, begin_ts: %lu, end_ts: %lu, begin_seq: %d, end_seq: %d\n",
#endif
								ri.second.packets, ri.second.ssrc, ri.second.first_ts, ri.second.last_ts, ri.second.first_seq, ri.second.last_seq);
					}
				}
				fclose(csv_file);
				if (params.verbose)
					std::cout << "=== RTP STREAMS INFO ===" << std::endl << std::endl;

				std::cout << "Output file produced: " << csv_path << std::endl;
			} while (false);

			return 0;
		}

        std::vector<rtp_info> srtp_streams;

        // Sorting by timestamps and filtering by ssrc rtp streams map
        for (auto &ri : params.srtp_streams) {
            if (ri.second.packets < 2 || ri.second.ssrc != params.ssrc) {
                continue;
            }
            srtp_streams.push_back(ri.second);
        }

        struct Sort_by_ts {
            bool operator() (const rtp_info& s1, const rtp_info& s2) {
                return (s1.first_ts < s2.first_ts);
            }
        } sort_by_ts_obj;

        std::sort(srtp_streams.begin(), srtp_streams.end(), sort_by_ts_obj);

        std::ofstream payload_file(output_path.c_str(), std::ofstream::out | std::ofstream::binary);

        uint8_t srtp_key[SRTP_MASTER_KEY_LEN];
        ParseKeyParams(keyBase64, srtp_key, sizeof(srtp_key));

        for (auto &ri : srtp_streams) {
            if (params.verbose) {
#ifdef WIN32
                printf("Found %06d RTP packets: ssrc: 0x%x, begin_ts: %llu, end_ts: %llu, begin_seq: %d, end_seq: %d\n",
                       ri.packets, ri.ssrc, ri.first_ts, ri.last_ts, ri.first_seq, ri.last_seq);
#else
                printf("Found %06d RTP packets: ssrc: 0x%x, begin_ts: %lu, end_ts: %lu, begin_seq: %d, end_seq: %d\n",
                       ri.packets, ri.ssrc, ri.first_ts, ri.last_ts, ri.first_seq, ri.last_seq);
#endif
            }

            std::string output_path_rtp(output_path);
            output_path_rtp += ".";
            output_path_rtp += std::to_string((int)ri.pt);
            output_path_rtp += ".rtp";
            std::ofstream rtp_file(output_path_rtp.c_str(), std::ofstream::out | std::ofstream::binary);

            SrtpSession srtp_decoder;
            srtp_decoder.Init();

            if (!srtp_decoder.SetRecv(SrtpCryptoSuiteFromName(sha), srtp_key, sizeof(srtp_key))) {
                std::cerr << "ERROR: can't set recv key!" << std::endl;
                throw std::runtime_error("SRTP fails");
            }

            auto count = 0;

            for (auto &i: ri.srtp_stream) {
                int rtp_length = 0;
                unsigned char *srtp_buffer = i.data();
                auto length = i.size();

                if (container) {
                    unsigned char sz[4];
                    int_to_char(length, sz);
                    rtp_file.write(reinterpret_cast<char*>(&sz[0]), 4);
                    int_to_char(0, sz);
                    rtp_file.write(reinterpret_cast<char*>(&sz[0]), 4);
                }
                rtp_file.write(reinterpret_cast<char*>(srtp_buffer), length);

                bool res = srtp_decoder.UnprotectRtp(srtp_buffer, length, &rtp_length);
                common_rtp_hdr_t *hdr = (common_rtp_hdr_t *)srtp_buffer;
                if (!res) {
                    std::cerr << " - seq=" << htons(hdr->seq) << std::endl;
                    continue;
                }

                auto rtp_header_size = sizeof(common_rtp_hdr_t);
                unsigned char* payload = srtp_buffer + rtp_header_size;
                if (params.verbose)
                    std::cout << "decrypt packet - seq=" << htons(hdr->seq) << std::endl;
                // has extension
                if (hdr->x) {
                    // If the X bit in the RTP header is one, a variable - length header
                    // extension MUST be appended to the RTP header, following the CSRC list if present.
                    common_rtp_hdr_ex_t* hdr_ex = (common_rtp_hdr_ex_t *)payload;
                    payload += sizeof(common_rtp_hdr_ex_t);

                    // calculate extensions RFC5285
                    int number_of_extensions = htons(hdr_ex->extension_len);
                    for (int n = 0; n < number_of_extensions; n++) {
                        rtp_hdr_ex5285_t* h5285 = (rtp_hdr_ex5285_t*)payload;
                        payload += sizeof(rtp_hdr_ex5285_t) + h5285->extension_len;
                    }

                    // There are as many
                    // extension elements as fit into the length as indicated in the RTP
                    // header extension length.Since this length is signaled in full 32 -
                    // bit words, padding bytes are used to pad to a 32 - bit boundary.
                    int extension_size = payload - srtp_buffer;
                    int padding = extension_size % 4;
                    payload += padding;
                }

                rtp_header_size = payload - srtp_buffer;
                ++count;
                size_t frame_size = rtp_length - rtp_header_size;

                if (container) {
                    unsigned char sz[4];
                    int_to_char(frame_size, sz);
                    payload_file.write(reinterpret_cast<char*>(&sz[0]), 4);
                    int_to_char(0, sz);
                    payload_file.write(reinterpret_cast<char*>(&sz[0]), 4);
                }
                // The array may contain null characters, which are also copied without stopping the copying process.
                payload_file.write(reinterpret_cast<char*>(payload), frame_size);
            }
            std::cout << "Wrote " << count << " payload chunks" << std::endl << std::endl;
            srtp_decoder.Terminate();
        }
        payload_file.close();
	}
	catch (std::exception const& err) {
		std::cerr << "Terminate: " << err.what() << std::endl;
		return 1;
	}
	return 0;
}

