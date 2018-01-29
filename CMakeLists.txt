cmake_minimum_required(VERSION 3.0)

###### Setup Hunter ######
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

###### END Setup Hunter ######

project(download-openssl)

hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)

add_executable(foo ${CMAKE_CURRENT_LIST_DIR}/sources/foo.cpp)

target_link_libraries(foo PUBLIC OpenSSL::SSL OpenSSL::Crypto)
