#!/bin/bash

PCAP_FILENAME=video_1920x1080

SSRC_A=0x1D3220A4
SSRC_B=0x1D3220A6
SSTP_A=ODEyMTQxYTEyMWRjZGRjMjllNTkwNjNkYjMzY2I4
SSTP_B=MWM3ZmI5NGYxOTBjNjU0ZWJjOTRmYmUwMWFiMDI2

ALG=AES_CM_128_HMAC_SHA1_80

../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_A.opus -s ${SSRC_A} -k ${SSTP_A} -r ${ALG} -c true 2>&1 >${PCAP_FILENAME}_A.log
../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_B.opus -s ${SSRC_B} -k ${SSTP_B} -r ${ALG} -c true 2>&1 >${PCAP_FILENAME}_B.log

