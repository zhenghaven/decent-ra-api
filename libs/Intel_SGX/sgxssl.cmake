cmake_minimum_required(VERSION 3.0)

set(OPENSSL_SOURCE_SHA256_EXPECTED "5835626cde9e99656585fc7aaa2302a73a7e1340bf8c14fd635a62c66802a517")
set(OPENSSL_SOURCE_VER 1.1.0h)
if(WIN32)
	set(SGX_SSL_BINARY_VER 1.9.100.0)
	set(SGX_SSL_BINARY_POSTFIX zip)
else()
	set(SGX_SSL_BINARY_VER 2.1.100.99999)
	set(SGX_SSL_BINARY_POSTFIX tar.gz)
endif()

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
	set(LINUX_LIB_ARCHI_STR "lib")
	set(WIN32_LIB_ARCHI_STR "Win32")
else()
	set(LINUX_LIB_ARCHI_STR "lib64")
	set(WIN32_LIB_ARCHI_STR "X64")
endif()

get_filename_component(SSL_PATH "${CMAKE_CURRENT_LIST_DIR}/intel-sgx-ssl" ABSOLUTE)
get_filename_component(SSL_BIN_PATH "${CMAKE_CURRENT_BINARY_DIR}/intel-sgx-ssl" ABSOLUTE)

if(WIN32)
	get_filename_component(SSL_WORK_DIR "${SSL_PATH}/Windows" ABSOLUTE)
else()
	get_filename_component(SSL_WORK_DIR "${SSL_PATH}/Linux" ABSOLUTE)
endif()

set(SSL_BUILD_DIR "${SSL_BIN_PATH}/build")
get_filename_component(SSL_ARCHIVE_PATH "${SSL_WORK_DIR}/sgxssl.${SGX_SSL_BINARY_VER}.${SGX_SSL_BINARY_POSTFIX}" ABSOLUTE)

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
	message(STATUS "==================================================")
	message(STATUS "Building Intel SGX SSL...")
	if(WIN32)
		execute_process(
			COMMAND build_all.cmd openssl-${OPENSSL_SOURCE_VER}
			WORKING_DIRECTORY "${SSL_WORK_DIR}"
			OUTPUT_FILE "${SSL_WORK_DIR}/build_output.txt"
			)
	else()
		execute_process(
			COMMAND ./build_sgxssl.sh
			WORKING_DIRECTORY "${SSL_WORK_DIR}"
			OUTPUT_FILE "${SSL_WORK_DIR}/build_output.txt"
			)
	endif()
	message(STATUS "Build completed. Build log can be found at ${SSL_WORK_DIR}/build_output.txt")
	message(STATUS "==================================================")
endif()

if(NOT EXISTS ${SSL_ARCHIVE_PATH})
	message(FATAL_ERROR "INTEL SGX SSL Build failed!!")
endif()

if(NOT EXISTS ${SSL_BUILD_DIR})
	file(MAKE_DIRECTORY ${SSL_BUILD_DIR})
endif()

execute_process(
	COMMAND ${CMAKE_COMMAND} -E tar xzf "${SSL_ARCHIVE_PATH}"
	WORKING_DIRECTORY ${SSL_BUILD_DIR}
)


############################
# SGX SSL Path
############################

# ${INTEL_SGX_SSL_INCLUDE_PATH}

# ${INTEL_SGX_SSL_LIB_WHOLE_ARC_DEBUG}
# ${INTEL_SGX_SSL_LIB_WHOLE_ARC_DEBUGSIM}
# ${INTEL_SGX_SSL_LIB_WHOLE_ARC_RELEASE}

# ${INTEL_SGX_SSL_LIB_GROUP_DEBUG}
# ${INTEL_SGX_SSL_LIB_GROUP_DEBUGSIM}
# ${INTEL_SGX_SSL_LIB_GROUP_RELEASE}

# ${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUG}
# ${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUGSIM}
# ${INTEL_SGX_SSL_LIB_UNTRUSTED_RELEASE}

get_filename_component(INTEL_SGX_SSL_INCLUDE_PATH "${SSL_BUILD_DIR}/include" ABSOLUTE)

if(WIN32)
	
	file(GLOB INTEL_SGX_SSL_LIB_WHOLE_ARC_DEBUG 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/debug/libsgx_tsgxssl.lib)
	
	file(GLOB INTEL_SGX_SSL_LIB_GROUP_DEBUG 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/debug/libsgx_tsgxssl_crypto.lib)
	
	file(GLOB INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUG 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/debug/libsgx_usgxssl.lib)
	set(INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUG ${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUG} Ws2_32.lib)
	
	################################################################################
	
	file(GLOB INTEL_SGX_SSL_LIB_WHOLE_ARC_DEBUGSIM 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/debug/libsgx_tsgxssl.lib)
	
	file(GLOB INTEL_SGX_SSL_LIB_GROUP_DEBUGSIM 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/debug/libsgx_tsgxssl_crypto.lib)
	
	file(GLOB INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUGSIM 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/debug/libsgx_usgxssl.lib)
	set(INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUGSIM ${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUGSIM} Ws2_32.lib)
	
	################################################################################
	
	file(GLOB INTEL_SGX_SSL_LIB_WHOLE_ARC_RELEASE 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/release/libsgx_tsgxssl.lib)
	
	file(GLOB INTEL_SGX_SSL_LIB_GROUP_RELEASE 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/release/libsgx_tsgxssl_crypto.lib)
	
	file(GLOB INTEL_SGX_SSL_LIB_UNTRUSTED_RELEASE 
				${SSL_BUILD_DIR}/lib/${WIN32_LIB_ARCHI_STR}/release/libsgx_usgxssl.lib)
	set(INTEL_SGX_SSL_LIB_UNTRUSTED_RELEASE ${INTEL_SGX_SSL_LIB_UNTRUSTED_RELEASE} Ws2_32.lib)
	
else()
	
	file(GLOB INTEL_SGX_SSL_LIB_WHOLE_ARC_DEBUG 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/debug/libsgx_tsgxssl.a)
	
	file(GLOB INTEL_SGX_SSL_LIB_GROUP_DEBUG 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/debug/libsgx_tsgxssl_crypto.a)
	
	file(GLOB INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUG 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/debug/libsgx_usgxssl.a)
	
	################################################################################
	
	file(GLOB INTEL_SGX_SSL_LIB_WHOLE_ARC_DEBUGSIM 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/debug/libsgx_tsgxssl.a)
	
	file(GLOB INTEL_SGX_SSL_LIB_GROUP_DEBUGSIM 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/debug/libsgx_tsgxssl_crypto.a)
	
	file(GLOB INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUGSIM 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/debug/libsgx_usgxssl.a)
	
	################################################################################
	
	file(GLOB INTEL_SGX_SSL_LIB_WHOLE_ARC_RELEASE 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/release/libsgx_tsgxssl.a)
	
	file(GLOB INTEL_SGX_SSL_LIB_GROUP_RELEASE 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/release/libsgx_tsgxssl_crypto.a)
	
	file(GLOB INTEL_SGX_SSL_LIB_UNTRUSTED_RELEASE 
				${SSL_BUILD_DIR}/${LINUX_LIB_ARCHI_STR}/release/libsgx_usgxssl.a)
	
endif()

