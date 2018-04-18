cmake_minimum_required(VERSION 3.0)

get_filename_component(SSL_PATH "${CMAKE_CURRENT_LIST_DIR}/intel-sgx-ssl" ABSOLUTE)
get_filename_component(SSL_BIN_PATH "${CMAKE_CURRENT_BINARY_DIR}/intel-sgx-ssl" ABSOLUTE)
set(OPENSSL_SOURCE_SHA256_EXPECTED "5835626cde9e99656585fc7aaa2302a73a7e1340bf8c14fd635a62c66802a517")

if(WIN32)
	get_filename_component(SSL_WORK_DIR "${SSL_PATH}/Windows" ABSOLUTE)
else()
	get_filename_component(SSL_WORK_DIR "${SSL_PATH}/Linux" ABSOLUTE)
endif()

get_filename_component(SSL_BUILD_DIR "${SSL_BIN_PATH}/build" ABSOLUTE)
get_filename_component(SSL_ARCHIVE_PATH "${SSL_WORK_DIR}/sgxssl.1.9.100.0.zip" ABSOLUTE)

if(EXISTS "${SSL_PATH}/openssl_source/openssl-1.1.0h.tar.gz")
	file(SHA256 ${SSL_PATH}/openssl_source/openssl-1.1.0h.tar.gz OPENSSL_SOURCE_SHA256)
endif()

if(NOT EXISTS "${SSL_PATH}/openssl_source/openssl-1.1.0h.tar.gz" OR NOT ${OPENSSL_SOURCE_SHA256} STREQUAL ${OPENSSL_SOURCE_SHA256_EXPECTED})
	file(DOWNLOAD 
		https://www.openssl.org/source/openssl-1.1.0h.tar.gz 
		${SSL_PATH}/openssl_source/openssl-1.1.0h.tar.gz 
		SHOW_PROGRESS
		)
endif()

file(SHA256 ${SSL_PATH}/openssl_source/openssl-1.1.0h.tar.gz OPENSSL_SOURCE_SHA256)

message(STATUS "OpenSSL Source SHA256: " ${OPENSSL_SOURCE_SHA256})
message(STATUS "Expected OpenSSL Source SHA256: " ${OPENSSL_SOURCE_SHA256_EXPECTED})

if(NOT ${OPENSSL_SOURCE_SHA256} STREQUAL ${OPENSSL_SOURCE_SHA256_EXPECTED})
	message(FATAL_ERROR "The OpenSSL just downloaded is not valid!!")
endif()

if(NOT EXISTS ${SSL_ARCHIVE_PATH})
	execute_process(
		COMMAND build_all.cmd openssl-1.1.0h
		WORKING_DIRECTORY "${SSL_PATH}/Windows"
		)
endif()

if(NOT EXISTS ${SSL_ARCHIVE_PATH})
	message(FATAL_ERROR "INTEL SGX SSL Build failed!!")
endif()

execute_process(
	COMMAND ${CMAKE_COMMAND} -E tar xzf "${SSL_ARCHIVE_PATH}"
	WORKING_DIRECTORY ${SSL_BUILD_DIR}
)