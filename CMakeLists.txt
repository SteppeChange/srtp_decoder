cmake_minimum_required(VERSION 3.0)
project(srtp_decoder)
# The version number
set (srtp_decoder_VERSION_MAJOR 1)
set (srtp_decoder_VERSION_MINOR 9)
# configure a header file to pass some of the CMake settings to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/src/srtp_decoder.h.in"
  "${PROJECT_SOURCE_DIR}/src/srtp_decoder.h"
  )

###############################################################################
## file globbing ##############################################################
###############################################################################

file(GLOB_RECURSE srtp_decoder_SOURCES
  src/base64.cpp
  src/decoder.cpp
  src/pcap_reader.cpp
  src/srtp_decoder.cpp
  src/headers.h
  )

###############################################################################
## target definitions #########################################################
###############################################################################

add_executable(srtp_decoder ${srtp_decoder_SOURCES})
target_compile_options(srtp_decoder PUBLIC -std=c++1y -Wall -Wfloat-conversion)

# this lets me include files relative to the root src dir with a <> pair
target_include_directories(srtp_decoder PUBLIC src)

###############################################################################
## dependencies ###############################################################
###############################################################################

if (NOT WIN32)

#################### DOCOPT ###################

find_package(docopt PATHS ${PROJECT_SOURCE_DIR}/.usr CONFIG REQUIRED)

if (docopt_FOUND)
	MESSAGE(STATUS "docopt package found")
	#FIXME: use native path
	set (docopt_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/.usr/include)
	#FIXME: use native path
	set (docopt_LIBS ${PROJECT_SOURCE_DIR}/.usr/lib/libdocopt.a)
else (docopt_FOUND)
	find_path(docopt_INCLUDE_DIRS
		NAMES docopt/docopt.h
		PATH_SUFFIXES include)

	find_library(docopt_LIBS
		NAMES docopt
		PATH_SUFFIXES bin lib)
endif (docopt_FOUND)

if (NOT docopt_INCLUDE_DIRS)
	MESSAGE(FATAL_ERROR "docopt_INCLUDE_DIRS not found")
else ()
	MESSAGE(STATUS "docopt include path found at: ${docopt_INCLUDE_DIRS}")
endif ()

if (NOT docopt_LIBS)
	MESSAGE(FATAL_ERROR "docopt_LIBS not found")
else ()
	MESSAGE(STATUS "docopt libs found at: ${docopt_LIBS}")
endif ()

include_directories(${docopt_INCLUDE_DIRS})
target_link_libraries(srtp_decoder PUBLIC ${docopt_LIBS})

#################### PCAP ###################

if (PCAP_INCLUDE_DIR)
	set(PCAP_FOUND TRUE)
else (PCAP_INCLUDE_DIR)
	find_program(PCAP_CONFIG_EXECUTABLE NAMES pcap-config PATHS)

	if (PCAP_CONFIG_EXECUTABLE)
		MESSAGE(STATUS "pcap-config found at: ${PCAP_CONFIG_EXECUTABLE}")
	else ()
		MESSAGE(FATAL_ERROR "pcap-config is required, but not found! Do you have libpcap >= 1.0?")
	endif ()

	exec_program(${PCAP_CONFIG_EXECUTABLE} ARGS --cflags OUTPUT_VARIABLE PCAP_CFLAGS )
	exec_program(${PCAP_CONFIG_EXECUTABLE} ARGS --libs   OUTPUT_VARIABLE PCAP_LIBRARIES )

	MESSAGE(STATUS "libpcap cflags: " ${PCAP_CFLAGS})
	MESSAGE(STATUS "libpcap libs: " ${PCAP_LIBRARIES})

	set(PCAP_FOUND TRUE)
endif (PCAP_INCLUDE_DIR)

if (PCAP_FOUND)
	target_link_libraries(srtp_decoder PUBLIC ${PCAP_LIBRARIES})
endif ()

################## SRTP ######################

find_path(SRTP_INCLUDE_DIRS
	NAMES srtp2/srtp.h
	PATH_SUFFIXES include)

#FIXME: use native path
set (SRTP_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/.usr/include)

if (NOT SRTP_INCLUDE_DIRS)
	MESSAGE(FATAL_ERROR "SRTP_INCLUDE_DIRS not found")
else()
	MESSAGE(STATUS "libsrtp found at: ${SRTP_INCLUDE_DIRS}")
endif()

if (SRTP_INCLUDE_DIRS)
	set(HAVE_SRTP_SRTP_H 1)
endif()

find_library(SRTP_LIBRARIES
	NAMES srtp2
	PATH_SUFFIXES bin lib)

#FIXME: use native path
set (SRTP_LIBRARIES ${PROJECT_SOURCE_DIR}/.usr/lib/libsrtp2.a)

if (NOT SRTP_LIBRARIES)
	MESSAGE(FATAL_ERROR "SRTP_LIBRARIES not found")
else()
	MESSAGE(STATUS "libsrtp libs found at: ${SRTP_LIBRARIES}")
endif()

include_directories(${SRTP_INCLUDE_DIRS})
target_link_libraries(srtp_decoder PUBLIC ${SRTP_LIBRARIES})

###############################################################################

endif (NOT WIN32)

###############################################################################
## packaging ##################################################################
###############################################################################

# all install commands get the same destination. this allows us to use paths
# relative to the executable.
install(TARGETS srtp_decoder DESTINATION example_destination)
# this is basically a repeat of the file copy instruction that copies the
# resources in the build directory, but here we tell cmake that we want it
# in the package
install(DIRECTORY resources DESTINATION example_destination)

# now comse everything we need, to create a package
# there are a lot more variables you can set, and some
# you need to set for some package types, but we want to
# be minimal here
set(CPACK_PACKAGE_NAME "srtp_decoder")
set(CPACK_PACKAGE_VERSION "1.0.0")

# we don't want to split our program up into several things
set(CPACK_MONOLITHIC_INSTALL 1)

# This must be last
include(CPack)
