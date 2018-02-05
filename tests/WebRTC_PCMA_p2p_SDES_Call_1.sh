#!/bin/bash

PCAP_FILENAME=WebRTC_PCMA_p2p_SDES_Call_1

SSRC_A=0xD092D296
SSRC_B=0x522B93AB
SSTP_A=7SYMKhu8sVMhCr4VXh+ZqkteB01QgqDSgLr4L9iU
SSTP_B=bhn3DDDcf7GhHEnFkGLW9V223XncT60nJrTQK06x

ALG=AES_CM_128_HMAC_SHA1_80

#../cmake-build-debug/srtp_decoder -v -l ${PCAP_FILENAME}.pcap 2>&1 > ${PCAP_FILENAME}.log
../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_A.pcma -s ${SSRC_A} -k ${SSTP_A} -r ${ALG} -c false -e udp 2>&1 > ${PCAP_FILENAME}_A.log
../.build/srtp_decoder -v -f ${PCAP_FILENAME}.pcap -o ${PCAP_FILENAME}_B.pcma -s ${SSRC_B} -k ${SSTP_B} -r ${ALG} -c false -e udp 2>&1 > ${PCAP_FILENAME}_B.log


