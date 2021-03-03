cmake_minimum_required(VERSION 3.14)
cmake_policy(SET CMP0026 OLD)
#==========================================================
#   Options for Decent Project
#==========================================================
option(DECENT_API_DECENT_SERVER "Add decent server module." OFF)
option(DECENT_API_DECENT_APP "Add decent app module." OFF)
option(DECENT_API_SGX_PLATFORM "Use SGX platform." ON)

if(APPLE)
	message(WARNING "Mac OS is not supported by Intel SGX for now. Trying to build in simulation mode...")
	set(CMAKE_BUILD_TYPE DebugSimulation)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

#==========================================================
#   Start Decent Project
#==========================================================
project(DecentRaApi)

#==========================================================
#   Setup options
#==========================================================

if (WIN32)
	macro(get_WIN32_WINNT version)
		if(CMAKE_SYSTEM_VERSION)
			set(ver ${CMAKE_SYSTEM_VERSION})
			string(REGEX MATCH "^([0-9]+).([0-9])" ver ${ver})
			string(REGEX MATCH "^([0-9]+)" verMajor ${ver})
			# Check for Windows 10, b/c we'll need to convert to hex 'A'.
			if("${verMajor}" MATCHES "10")
				set(verMajor "A")
				string(REGEX REPLACE "^([0-9]+)" ${verMajor} ver ${ver})
			endif()
			# Remove all remaining '.' characters.
			string(REPLACE "." "" ver ${ver})
			# Prepend each digit with a zero.
			string(REGEX REPLACE "([0-9A-Z])" "0\\1" ver ${ver})
			set(${version} "0x${ver}")
		endif()
	endmacro()

	get_WIN32_WINNT(win_ver)
	message(STATUS "CMAKE_SYSTEM_VERSION: " "${CMAKE_SYSTEM_VERSION}")
	message(STATUS "_WIN32_WINNT: " "${win_ver}")
	add_definitions(-D_WIN32_WINNT=${win_ver})
endif(WIN32)

if(MSVC)
	set(COMMON_OPTIONS /W3 /wd4996 /we4239 /we4002 /we4700 /we4305 /EHsc /MP)
	set(DEBUG_OPTIONS /MTd /Od /Zi /DDEBUG)
	set(SIMULATE_OPTIONS /DSIMULATING_ENCLAVE)
	set(RELEASE_OPTIONS /MT /Ox /Oi /Ob2 /fp:fast /GR- /DEDEBUG)# /DNDEBUG
	
	set(COMMON_ENCLAVE_CXX_OPTIONS )
	
	set(ENCLAVE_LINKER_OPTIONS "/NODEFAULTLIB /NOENTRY")
	set(APP_DEBUG_LINKER_OPTIONS "/NODEFAULTLIB:libc.lib /NODEFAULTLIB:libcmt.lib /NODEFAULTLIB:msvcrt.lib /NODEFAULTLIB:libcd.lib /NODEFAULTLIB:msvcrtd.lib")
	set(APP_RELEASE_LINKER_OPTIONS "/NODEFAULTLIB:libc.lib /NODEFAULTLIB:libcmtd.lib /NODEFAULTLIB:msvcrt.lib /NODEFAULTLIB:libcd.lib /NODEFAULTLIB:msvcrtd.lib")
	
	set(COMMON_APP_DEFINES WIN32_LEAN_AND_MEAN CURL_STATICLIB BOOST_DATE_TIME_NO_LIB)
	
	set(Additional_Sys_Lib )
else()
	set(COMMON_OPTIONS -pthread)
	set(DEBUG_OPTIONS -O0 -g -DDEBUG -UNDEBUG -UEDEBUG)
	set(SIMULATE_OPTIONS -DSIMULATING_ENCLAVE)
	set(RELEASE_OPTIONS -O2 -DEDEBUG -UDEBUG) #-DNDEBUG defined by default
	
	set(COMMON_ENCLAVE_CXX_OPTIONS -std=c++11)
	
	set(ENCLAVE_LINKER_OPTIONS "")
	set(APP_DEBUG_LINKER_OPTIONS "")
	set(APP_RELEASE_LINKER_OPTIONS "")
	
	set(COMMON_APP_DEFINES CURL_STATICLIB BOOST_DATE_TIME_NO_LIB)
	
	set(Additional_Sys_Lib rt pthread)
endif()

set(DEBUG_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS})
set(DEBUGSIM_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS} ${SIMULATE_OPTIONS})
set(RELEASE_OPTIONS ${COMMON_OPTIONS} ${RELEASE_OPTIONS})

if(MSVC)
	set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /DEBUG")
endif()

add_compile_options(
	"$<$<CONFIG:Debug>:${DEBUG_OPTIONS}>"
	"$<$<CONFIG:DebugSimulation>:${DEBUGSIM_OPTIONS}>"
	"$<$<CONFIG:Release>:${RELEASE_OPTIONS}>"
)

#Remove all standard libraries dependency here so that enclave DLL can be 
# compiled properly. And it will be added back later for non-enclave apps.
set(COMMON_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES_INIT}")
separate_arguments(COMMON_STANDARD_LIBRARIES)
set(CMAKE_CXX_STANDARD_LIBRARIES "")
set(CMAKE_C_STANDARD_LIBRARIES "")

if(MSVC) 
	#Removed Basic Runtime Checks in MSVC
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
endif()

set(CMAKE_CXX_FLAGS_DEBUGSIMULATION ${CMAKE_CXX_FLAGS_DEBUG})
set(CMAKE_C_FLAGS_DEBUGSIMULATION ${CMAKE_C_FLAGS_DEBUG})
set(CMAKE_EXE_LINKER_FLAGS_DEBUGSIMULATION ${CMAKE_EXE_LINKER_FLAGS_DEBUG})
set(CMAKE_SHARED_LINKER_FLAGS_DEBUGSIMULATION ${CMAKE_SHARED_LINKER_FLAGS_DEBUG})
set(CMAKE_STATIC_LINKER_FLAGS_DEBUGSIMULATION ${CMAKE_STATIC_LINKER_FLAGS_DEBUG})

set(CMAKE_CONFIGURATION_TYPES Release Debug DebugSimulation)
set_property(GLOBAL PROPERTY DEBUG_CONFIGURATIONS Debug DebugSimulation)

#==========================================================
#   Add Libraries
#==========================================================
set(BUILD_SHARED_LIBS OFF)
set(BUILD_STATIC_LIBS ON)
set(USE_MSVC_RUNTIME_LIBRARY_DLL OFF)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)
set(Boost_NO_SYSTEM_PATHS ON)

#==========================================================
#   Add submodules
#==========================================================

include(FetchContent)

## Boost libraries
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/config)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/predef)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/preprocessor)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/assert)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/io)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/core)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/static_assert)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/throw_exception)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/integer)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/move)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/type_traits)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/typeof)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/concept_check)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/detail)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/tuple)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/container_hash)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/intrusive)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/container)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/utility)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/optional)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/smart_ptr)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/conversion)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/mpl)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/function_types)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/fusion)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/iterator)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/exception)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/winapi)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/system)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/boost/filesystem)

## mbedTLS
set(ENABLE_TESTING OFF CACHE BOOL "Build mbed TLS tests." FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Build mbed TLS programs." FORCE)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/mbedtls)
set(MBEDCRYPTO_LIBRARY mbedcrypto)
set(MBEDX509_LIBRARY mbedx509)
set(MBEDTLS_LIBRARY mbedtls)
set(MBEDCRYPTO_ENCLAVE_LIBRARY mbedcrypto_enclave)
set(MBEDX509_ENCLAVE_LIBRARY mbedx509_enclave)
set(MBEDTLS_ENCLAVE_LIBRARY mbedtls_enclave)
set(MBEDTLS_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/libs/mbedtls/include)
install(TARGETS mbedcrypto mbedx509 mbedtls EXPORT "CURLTargets")

## mbedTLScpp
FetchContent_Declare(
  git_mbedtlscpp
  GIT_REPOSITORY https://github.com/zhenghaven/mbedTLScpp.git
  GIT_TAG        v0.1.9a
)
FetchContent_MakeAvailable(git_mbedtlscpp)
include($ENV{MBEDTLSCPP_HOME}/cmake/mbedTLScpp_UseMbedtlsHeaders.cmake)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedcrypto)
mbedTLScpp_UseMbedtlsHeaders_Enclave(mbedcrypto_enclave)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedx509)
mbedTLScpp_UseMbedtlsHeaders_Enclave(mbedx509_enclave)
mbedTLScpp_UseMbedtlsHeaders_Normal(mbedtls)
mbedTLScpp_UseMbedtlsHeaders_Enclave(mbedtls_enclave)

##libcurl
set(BUILD_CURL_EXE OFF CACHE BOOL "Set to ON to build CURL executable." FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Set to ON to build libcurl test libraries." FORCE)
set(CURL_STATICLIB ON CACHE BOOL "Set to ON to build libcurl with static linking." FORCE)
set(CURL_ZLIB OFF CACHE BOOL "Set to ON to enable building curl with zlib support." FORCE)
set(CMAKE_USE_LIBSSH2 OFF CACHE BOOL "Set to ON to enable building curl with libSSH2 support." FORCE)
set(CMAKE_USE_OPENSSL OFF CACHE BOOL "Set to ON to build libcurl with OpenSSL." FORCE)
set(CMAKE_USE_MBEDTLS ON CACHE BOOL "Set to ON to build libcurl with MbedTLS." FORCE)
set(HTTP_ONLY ON CACHE BOOL "Set to ON to build libcurl with only http functionalities." FORCE)
set(ENABLE_MANUAL OFF CACHE BOOL "Set to ON to build libcurl manual." FORCE)
set(ENABLE_UNIX_SOCKETS OFF CACHE BOOL "Define if you want Unix domain sockets support" FORCE)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/curl)
set(CURL_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/curl/include)
target_include_directories(libcurl INTERFACE $<BUILD_INTERFACE:${CURL_INCLUDE_DIR}>)

##JsonCPP
set(JSONCPP_WITH_TESTS OFF CACHE BOOL "Set to ON to build JsonCpp with tests." FORCE)
set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "Set to ON to build JsonCpp with unit tests." FORCE)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/jsoncpp)

##Intel SGX SDK
include(SetupSgxSdkLibs)

##Header only libraries
set(CPPCODEC_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/cppcodec)
set(RAPIDJSON_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/rapidjson/include)
set(BOOST_TTI_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/boost/tti/include)
set(BOOST_UUID_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/boost/uuid/include)
set(BOOST_ASIO_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/boost/asio/include)
set(BOOST_RANDOM_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/boost/random/include)
set(BOOST_INTERPROC_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/boost/interprocess/include)
set(BOOST_UNORDERED_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/boost/unordered/include)
set(BOOST_DATE_TIME_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/boost/date_time/include)
set(BOOST_NUMERIC_CONVERSION_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/boost/numeric_conversion/include)

#==========================================================
#   Add files
#==========================================================

set(SOURCES_DIR_PATH ${CMAKE_CURRENT_LIST_DIR}/sources)
set(DECENT_API_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/sources)

file(GLOB_RECURSE SOURCES ${SOURCES_DIR_PATH}/DecentApi/*.[ch]* ${SOURCES_DIR_PATH}/DecentApi/*.edl)

# Common files:
file(GLOB_RECURSE SOURCES_COMMON ${SOURCES_DIR_PATH}/DecentApi/Common/*.[ch]*)
file(GLOB_RECURSE SOURCES_COMMON_APP ${SOURCES_DIR_PATH}/DecentApi/CommonApp/*.[ch]*)
file(GLOB_RECURSE SOURCES_COMMON_ENCLAVE ${SOURCES_DIR_PATH}/DecentApi/CommonEnclave/*.[ch]*)
file(GLOB_RECURSE SOURCES_APP_APP ${SOURCES_DIR_PATH}/DecentApi/DecentAppApp/*.[ch]*)
file(GLOB_RECURSE SOURCES_APP_ENCLAVE ${SOURCES_DIR_PATH}/DecentApi/DecentAppEnclave/*.[ch]*)
file(GLOB_RECURSE SOURCES_SERVER_APP ${SOURCES_DIR_PATH}/DecentApi/DecentServerApp/*.[ch]*)
file(GLOB_RECURSE SOURCES_SERVER_ENCLAVE ${SOURCES_DIR_PATH}/DecentApi/DecentServerEnclave/*.[ch]*)
file(GLOB_RECURSE SOURCES_COMMON_EDL ${SOURCES_DIR_PATH}/DecentApi/EDL/*.edl)

set(DECENT_API_EDL_DIR ${SOURCES_DIR_PATH}/DecentApi/EDL PARENT_SCOPE)

#==========================================================
#   Setup filters
#==========================================================

source_group(TREE ${SOURCES_DIR_PATH}/DecentApi FILES ${SOURCES})

#==========================================================
#   Enclave Projects
#==========================================================

if(DECENT_API_DECENT_APP)
	add_library(DecentRa_App_Enclave STATIC ${SOURCES_APP_ENCLAVE} ${SOURCES_COMMON_ENCLAVE} ${SOURCES_COMMON})
	#includes:
	target_include_directories(DecentRa_App_Enclave BEFORE PRIVATE ${INTEL_SGX_SDK_INCLUDE_DIRS})
	target_include_directories(DecentRa_App_Enclave
									PUBLIC
										${CPPCODEC_INCLUDE_DIR}
										${RAPIDJSON_INCLUDE_DIR}
										${SOURCES_DIR_PATH}/DecentApi/config-headers
									INTERFACE
										${DECENT_API_INCLUDE_DIR}
	)
	#defines:
	target_compile_definitions(DecentRa_App_Enclave
									PUBLIC
										ENCLAVE_ENVIRONMENT
										ENCLAVE_SGX_ENVIRONMENT
										RAPIDJSON_ALLOCATOR_DEFAULT_CHUNK_CAPACITY=1024
										MBEDTLSCPP_CUSTOMIZED_DEFAULT_RBG="DecentApiMbedtlsRbg.hpp"
										MBEDTLSCPP_CUSTOMIZED_THREADING_INIT="DecentApiMbedtlsMutex.hpp"
	)
	#compiler flags:
	target_compile_options(DecentRa_App_Enclave PRIVATE ${INTEL_SGX_SDK_C_FLAGS} $<$<COMPILE_LANGUAGE:CXX>:${INTEL_SGX_SDK_CXX_FLAGS} ${COMMON_ENCLAVE_CXX_OPTIONS}>)
	#linker flags:
	set_target_properties(DecentRa_App_Enclave PROPERTIES LINK_FLAGS "${ENCLAVE_LINKER_OPTIONS} ${INTEL_SGX_SDK_LINKER_FLAGS_T}")
    set_target_properties(DecentRa_App_Enclave PROPERTIES FOLDER "DecentRaApi")
	
	target_link_libraries(DecentRa_App_Enclave 
		mbedtls_enclave 
		mbedTLScpp
	)
	
	add_library(DecentRa_App_App STATIC ${SOURCES_APP_APP} ${SOURCES_COMMON_APP} ${SOURCES_COMMON})
	#includes:
	target_include_directories(DecentRa_App_App 
									PRIVATE
										${INTEL_SGX_SDK_INCLUDE_DIR}
									PUBLIC
										${CPPCODEC_INCLUDE_DIR}
										${BOOST_TTI_INCLUDE_DIR}
										${BOOST_UUID_INCLUDE_DIR}
										${BOOST_ASIO_INCLUDE_DIR}
										${BOOST_RANDOM_INCLUDE_DIR}
										${BOOST_INTERPROC_INCLUDE_DIR}
										${BOOST_DATE_TIME_INCLUDE_DIR}
										${BOOST_UNORDERED_INCLUDE_DIR}
										${BOOST_NUMERIC_CONVERSION_INCLUDE_DIR}
									INTERFACE
										${DECENT_API_INCLUDE_DIR})
	#defines:
	target_compile_definitions(DecentRa_App_App PRIVATE ${COMMON_APP_DEFINES})
	#linker flags:
	set_target_properties(DecentRa_App_App PROPERTIES LINK_FLAGS_DEBUG "${APP_DEBUG_LINKER_OPTIONS}")
	set_target_properties(DecentRa_App_App PROPERTIES LINK_FLAGS_DEBUGSIMULATION "${APP_DEBUG_LINKER_OPTIONS}")
	set_target_properties(DecentRa_App_App PROPERTIES LINK_FLAGS_RELEASE "${APP_RELEASE_LINKER_OPTIONS}")
    set_target_properties(DecentRa_App_App PROPERTIES FOLDER "DecentRaApi")

	target_link_libraries(DecentRa_App_App 
		${COMMON_STANDARD_LIBRARIES} 
		jsoncpp_lib_static 
		libcurl 
		mbedtls 
		mbedTLScpp
		Boost::container
		Boost::smart_ptr
		Boost::exception
		Boost::system
		Boost::filesystem
		${Additional_Sys_Lib}
	)
endif()

if(DECENT_API_DECENT_SERVER)
	add_library(DecentRa_Server_Enclave STATIC ${SOURCES_SERVER_ENCLAVE} ${SOURCES_COMMON_ENCLAVE} ${SOURCES_COMMON})
	#includes:
	target_include_directories(DecentRa_Server_Enclave BEFORE PRIVATE ${INTEL_SGX_SDK_INCLUDE_DIRS})
	target_include_directories(DecentRa_Server_Enclave
									PUBLIC
										${CPPCODEC_INCLUDE_DIR}
										${RAPIDJSON_INCLUDE_DIR}
										${SOURCES_DIR_PATH}/DecentApi/config-headers
									INTERFACE
										${DECENT_API_INCLUDE_DIR}
	)
	#defines:
	target_compile_definitions(DecentRa_Server_Enclave
									PUBLIC
										ENCLAVE_ENVIRONMENT
										ENCLAVE_SGX_ENVIRONMENT
										RAPIDJSON_ALLOCATOR_DEFAULT_CHUNK_CAPACITY=1024
										MBEDTLSCPP_CUSTOMIZED_DEFAULT_RBG="DecentApiMbedtlsRbg.hpp"
										MBEDTLSCPP_CUSTOMIZED_THREADING_INIT="DecentApiMbedtlsMutex.hpp"
	)
	#compiler flags:
	target_compile_options(DecentRa_Server_Enclave PRIVATE ${INTEL_SGX_SDK_C_FLAGS} $<$<COMPILE_LANGUAGE:CXX>:${INTEL_SGX_SDK_CXX_FLAGS} ${COMMON_ENCLAVE_CXX_OPTIONS}>)
	#linker flags:
	set_target_properties(DecentRa_Server_Enclave PROPERTIES LINK_FLAGS "${ENCLAVE_LINKER_OPTIONS} ${INTEL_SGX_SDK_LINKER_FLAGS_T}")
    set_target_properties(DecentRa_Server_Enclave PROPERTIES FOLDER "DecentRaApi")
	set_property(TARGET DecentRa_Server_Enclave APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${DECENT_API_INCLUDE_DIR}")
	
	target_link_libraries(DecentRa_Server_Enclave 
		mbedtls_enclave 
		mbedTLScpp
	)
	
	add_library(DecentRa_Server_App STATIC ${SOURCES_SERVER_APP} ${SOURCES_COMMON_APP} ${SOURCES_COMMON})
	#includes:
	target_include_directories(DecentRa_Server_App
									PRIVATE
										${INTEL_SGX_SDK_INCLUDE_DIR}
									PUBLIC
										${CPPCODEC_INCLUDE_DIR}
										${BOOST_TTI_INCLUDE_DIR}
										${BOOST_UUID_INCLUDE_DIR}
										${BOOST_ASIO_INCLUDE_DIR}
										${BOOST_RANDOM_INCLUDE_DIR}
										${BOOST_INTERPROC_INCLUDE_DIR}
										${BOOST_DATE_TIME_INCLUDE_DIR}
										${BOOST_UNORDERED_INCLUDE_DIR}
										${BOOST_NUMERIC_CONVERSION_INCLUDE_DIR}
									INTERFACE
										${DECENT_API_INCLUDE_DIR})
	#defines:
	target_compile_definitions(DecentRa_Server_App PRIVATE ${COMMON_APP_DEFINES})
	#linker flags:
	set_target_properties(DecentRa_Server_App PROPERTIES LINK_FLAGS_DEBUG "${APP_DEBUG_LINKER_OPTIONS}")
	set_target_properties(DecentRa_Server_App PROPERTIES LINK_FLAGS_DEBUGSIMULATION "${APP_DEBUG_LINKER_OPTIONS}")
	set_target_properties(DecentRa_Server_App PROPERTIES LINK_FLAGS_RELEASE "${APP_RELEASE_LINKER_OPTIONS}")
    set_target_properties(DecentRa_Server_App PROPERTIES FOLDER "DecentRaApi")

	target_link_libraries(DecentRa_Server_App 
		${COMMON_STANDARD_LIBRARIES} 
		jsoncpp_lib_static 
		libcurl 
		mbedtls 
		mbedTLScpp
		Boost::container
		Boost::smart_ptr
		Boost::exception
		Boost::system
		Boost::filesystem
		${Additional_Sys_Lib}
	)
endif()
