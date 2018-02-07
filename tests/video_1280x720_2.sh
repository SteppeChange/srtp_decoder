#!/bin/bash

PCAP_FILENAME=video_1280x720_2

SSRC_A=0x36EDBF05;
SSRC_V=0x4e641d32;
SSTP_A=YzViYzdlNmZkMDljODg2ZmMwZGMyZDU0MTQxODA5;
SSTP_B=ZTUyNDkzMDAzMWVmZGU3ZjE5MDAyMmM4MWU0ODE5;

ALG=AES_CM_128_HMAC_SHA1_80

../.build/srtp_decoder -l -f ${PCAP_FILENAME}.pcap
../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_ssrc_${SSRC_A}.opus -s ${SSRC_A} -k ${SSTP_A} -r ${ALG} -c true 2>&1 >${PCAP_FILENAME}_A.log
../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_ssrc_${SSRC_V}.h264 -s ${SSRC_V} -k ${SSTP_A} -r ${ALG} -c true 2>&1 >${PCAP_FILENAME}_V.log
