cmake_minimum_required(VERSION 3.0)

### Setup Hunter ###
set(gate_dir "${CMAKE_CURRENT_LIST_DIR}/hunter/gate")
set(gate_module "${gate_dir}/cmake/HunterGate.cmake")

get_filename_component(gate_module "${gate_module}" ABSOLUTE)
if(NOT EXISTS "${gate_module}")
	message(
		FATAL_ERROR
		"${gate_module} module not found!"
	)
endif()

message("Including HunterGate: ${gate_module}")
include("${gate_module}")

get_filename_component(HUNTER_ROOT "${CMAKE_CURRENT_LIST_DIR}/hunter" ABSOLUTE)
HunterGate(URL "x" SHA1 "xxxxxxxx" ${TESTING_CONFIG_OPT})

### END Setup Hunter ###


project(download-openssl)

### Setup options ###

OPTION(BUILD_SHARED_LIBS "Build shared libraries" OFF)
OPTION(BUILD_STATIC_LIBS "Build static libraries" ON)
option(USE_MSVC_RUNTIME_LIBRARY_DLL OFF)
option(JSONCPP_WITH_TESTS OFF)
option(JSONCPP_WITH_POST_BUILD_UNITTEST OFF)

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(json_LIB jsoncpp_lib_static)

if(OPENSSL_USE_STATIC_LIBS)
	message("Using static openssl lib.")
else()
	message("Using shared openssl lib!!!")
endif()

### END Setup options ###

### Add Sub-modules ###

###### Add from Hunter ######
hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)

###### END Add from Hunter ######

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/jsoncpp)

include_directories(${JSONCPP_INCLUDE_DIRS})

### END Add Sub-modules ###

add_executable(foo ${CMAKE_CURRENT_LIST_DIR}/sources/foo.cpp)

target_link_libraries(foo OpenSSL::SSL OpenSSL::Crypto jsoncpp_lib_static)
