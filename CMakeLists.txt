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


project(decent)

### Setup options ###

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_STATIC_LIBS "Build static libraries" ON)
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

if(MSVC)
	set(COMMON_OPTIONS /W3 /wd4996 /we4239 /we4002 /we4700 /we4305 /EHsc /MP)
	set(ENCLAVE_OPTIONS /NODEFAULTLIB /NOENTRY)
	set(DEBUG_OPTIONS /MTd /Od /Zi)
	set(RELEASE_OPTIONS /MT /Ox /fp:fast /GL /GR-)
elseif(APPLE)
	set(COMMON_OPTIONS )
	set(DEBUG_OPTIONS -O0 -g)
	set(RELEASE_OPTIONS -O2)
else()
	set(COMMON_OPTIONS )
	set(DEBUG_OPTIONS -O0 -g)
	set(RELEASE_OPTIONS -O2)
endif()

set(DEBUG_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS})
set(DEBUGSIM_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS})
set(RELEASE_OPTIONS ${COMMON_OPTIONS} ${RELEASE_OPTIONS})

add_compile_options(
	"$<$<CONFIG:Debug>:${DEBUG_OPTIONS}>"
	"$<$<CONFIG:DebugSimulation>:${DEBUGSIM_OPTIONS}>"
	"$<$<CONFIG:Release>:${RELEASE_OPTIONS}>"
)
if(MSVC)
	set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /DEBUG")
	set(CMAKE_EXE_LINKER_FLAGS_DEBUGSIMULATION "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /DEBUG")
	set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /LTCG /INCREMENTAL:NO")
endif()

set(CMAKE_CXX_FLAGS_DEBUGSIMULATION ${CMAKE_CXX_FLAGS_DEBUG} /Od)
set(CMAKE_C_FLAGS_DEBUGSIMULATION ${CMAKE_C_FLAGS_DEBUG} /Od)
set(CMAKE_EXE_LINKER_FLAGS_DEBUGSIMULATION ${CMAKE_EXE_LINKER_FLAGS_DEBUG})
set(CMAKE_SHARED_LINKER_FLAGS_DEBUGSIMULATION ${CMAKE_SHARED_LINKER_FLAGS_DEBUG})

set(CMAKE_CONFIGURATION_TYPES Release Debug DebugSimulation)


### END Setup options ###

### Add Sub-modules ###

###### Add from Hunter ######
hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)

###### END Add from Hunter ######

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/jsoncpp)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/Intel_SGX)

include_directories(${JSONCPP_INCLUDE_DIRS})
include_directories(${INTEL_SGX_INCLUDE_DIRS})

### END Add Sub-modules ###

add_executable(LibTestApp ${CMAKE_CURRENT_LIST_DIR}/sources/LibTestApp.cpp)

target_link_libraries(LibTestApp 
					OpenSSL::SSL 
					OpenSSL::Crypto 
					"$<$<CONFIG:Debug>:${INTEL_SGX_DEBUG_UNTRUST_LIB}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_DEBUGSIM_UNTRUST_LIB}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_RELEASE_UNTRUST_LIB}>" 
					jsoncpp_lib_static
					)
