#!/bin/bash

PCAP_FILENAME=video_1920x1080

SSRC_A=0x1D3220A4
SSRC_V=0x65fef922
SSTP_A=ODEyMTQxYTEyMWRjZGRjMjllNTkwNjNkYjMzY2I4
SSTP_B=MWM3ZmI5NGYxOTBjNjU0ZWJjOTRmYmUwMWFiMDI2

ALG=AES_CM_128_HMAC_SHA1_80

../.build/srtp_decoder -l -f ${PCAP_FILENAME}.pcap
../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_ssrc_${SSRC_A}.opus -s ${SSRC_A} -k ${SSTP_A} -r ${ALG} -c true 2>&1 >${PCAP_FILENAME}_A.log
../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_ssrc_${SSRC_V}.h264 -s ${SSRC_V} -k ${SSTP_A} -r ${ALG} -c false 2>&1 >${PCAP_FILENAME}_V.log

