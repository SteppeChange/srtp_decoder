#!/bin/bash

PCAP_FILENAME=udp_call_02_03_client

SSRC_A=0x1C065362
SSRC_B=0x1C065364
SSTP_A=NjZiYTBmY2FmOGE2ZGU3MmVlMzM4ZDQ0OGVhMTI0
SSTP_B=YTEzNjhhMTNmNWUxMjljZTg3MTEyNWQ2YTE2ODQ2

ALG=AES_CM_128_HMAC_SHA1_80

../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_A.opus -s ${SSRC_A} -k ${SSTP_A} -r ${ALG} -c true 2>&1 >${PCAP_FILENAME}_A.log
../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_B.opus -s ${SSRC_B} -k ${SSTP_B} -r ${ALG} -c true 2>&1 >${PCAP_FILENAME}_B.log

