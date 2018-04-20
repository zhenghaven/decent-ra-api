cmake_minimum_required(VERSION 3.0)

set(OPENSSL_SOURCE_SHA256_EXPECTED "5835626cde9e99656585fc7aaa2302a73a7e1340bf8c14fd635a62c66802a517")
set(OPENSSL_SOURCE_VER 1.1.0h)
set(SGX_SSL_BINARY_VER 1.9.100.0)

get_filename_component(SSL_PATH "${CMAKE_CURRENT_LIST_DIR}/intel-sgx-ssl" ABSOLUTE)
get_filename_component(SSL_BIN_PATH "${CMAKE_CURRENT_BINARY_DIR}/intel-sgx-ssl" ABSOLUTE)

if(WIN32)
	get_filename_component(SSL_WORK_DIR "${SSL_PATH}/Windows" ABSOLUTE)
else()
	get_filename_component(SSL_WORK_DIR "${SSL_PATH}/Linux" ABSOLUTE)
endif()

set(SSL_BUILD_DIR "${SSL_BIN_PATH}/build")
get_filename_component(SSL_ARCHIVE_PATH "${SSL_WORK_DIR}/sgxssl.${SGX_SSL_BINARY_VER}.zip" ABSOLUTE)

if(EXISTS "${SSL_PATH}/openssl_source/openssl-${OPENSSL_SOURCE_VER}.tar.gz")
	file(SHA256 ${SSL_PATH}/openssl_source/openssl-${OPENSSL_SOURCE_VER}.tar.gz OPENSSL_SOURCE_SHA256)
endif()

if(NOT EXISTS "${SSL_PATH}/openssl_source/openssl-${OPENSSL_SOURCE_VER}.tar.gz" OR NOT ${OPENSSL_SOURCE_SHA256} STREQUAL ${OPENSSL_SOURCE_SHA256_EXPECTED})
	file(DOWNLOAD 
		https://www.openssl.org/source/openssl-${OPENSSL_SOURCE_VER}.tar.gz 
		${SSL_PATH}/openssl_source/openssl-${OPENSSL_SOURCE_VER}.tar.gz 
		SHOW_PROGRESS
		)
endif()

file(SHA256 ${SSL_PATH}/openssl_source/openssl-${OPENSSL_SOURCE_VER}.tar.gz OPENSSL_SOURCE_SHA256)

message(STATUS "OpenSSL Source SHA256: " ${OPENSSL_SOURCE_SHA256})
message(STATUS "Expected OpenSSL Source SHA256: " ${OPENSSL_SOURCE_SHA256_EXPECTED})

if(NOT ${OPENSSL_SOURCE_SHA256} STREQUAL ${OPENSSL_SOURCE_SHA256_EXPECTED})
	message(FATAL_ERROR "The OpenSSL just downloaded is not valid!!")
endif()

if(NOT EXISTS ${SSL_ARCHIVE_PATH})
	if(WIN32)
		execute_process(
			COMMAND build_all.cmd openssl-${OPENSSL_SOURCE_VER}
			WORKING_DIRECTORY "${SSL_WORK_DIR}"
			OUTPUT_FILE "${SSL_WORK_DIR}/build_output.txt"
			)
#	else()
#		execute_process(
#			COMMAND ./build_sgxssl.sh
#			WORKING_DIRECTORY "${SSL_WORK_DIR}"
#			OUTPUT_FILE "${SSL_WORK_DIR}/build_output.txt"
#			)
	endif()
endif()

#if(NOT EXISTS ${SSL_ARCHIVE_PATH})
#	message(FATAL_ERROR "INTEL SGX SSL Build failed!!")
#endif()

#if(NOT EXISTS ${SSL_BUILD_DIR})
#	file(MAKE_DIRECTORY ${SSL_BUILD_DIR})
#endif()

#execute_process(
#	COMMAND ${CMAKE_COMMAND} -E tar xzf "${SSL_ARCHIVE_PATH}"
#	WORKING_DIRECTORY ${SSL_BUILD_DIR}
#)
