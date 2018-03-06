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
	set(DEBUG_OPTIONS /MTd /Od /Zi)
	set(RELEASE_OPTIONS /MT /Ox /fp:fast /GL /GR-)
	
	set(ENCLAVE_OPTIONS "/NODEFAULTLIB /NOENTRY")
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


message(STATUS "==================================================")
message(STATUS "CMake Standard Libraries:")
message(STATUS "${CMAKE_CXX_STANDARD_LIBRARIES_INIT}")
message(STATUS "CMake CXX Flags (Debug):")
message(STATUS "${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMake CXX Flags (Release):")
message(STATUS "${CMAKE_CXX_FLAGS_RELEASE}")
message(STATUS "==================================================")

#Remove all standard libraries dependency here so that enclave DLL can be 
# compiled properly. And it will be added back later for non-enclave apps.
set(COMMON_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES_INIT}")
separate_arguments(COMMON_STANDARD_LIBRARIES)
set(CMAKE_CXX_STANDARD_LIBRARIES "")
set(CMAKE_C_STANDARD_LIBRARIES "")

if(MSVC) 
	#Removed Basic Runtime Checks in MSVC
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_DEBUGSIMULATION "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUGSIMULATION "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_DEBUG}")
endif()

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

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(WIN_ARCHI_STR "x64")
	set(LINUX_ARCHI_STR "x64")
else()
	set(WIN_ARCHI_STR "win32")
	set(LINUX_ARCHI_STR "x86")
endif()

if(MSVC)
	set(SGX_SDK_PATH "$ENV{SGXSDKInstallPath}")
	set(SGX_EDGER_PATH "$ENV{SGXSDKInstallPath}/bin/win32/Release/sgx_edger8r.exe")
	set(SGX_SIGN_PATH "$ENV{SGXSDKInstallPath}/bin/win32/Release/sgx_sign.exe")
elseif(APPLE)
	set(SGX_SDK_PATH "$ENV{SGX_SDK}")
	set(SGX_EDGER_PATH "$ENV{SGX_SDK}/bin/${LINUX_ARCHI_STR}/sgx_edger8r")
	set(SGX_SIGN_PATH "$ENV{SGX_SDK}/bin/${LINUX_ARCHI_STR}/sgx_sign")
	
else()
	set(SGX_SDK_PATH "$ENV{SGX_SDK}")
	set(SGX_EDGER_PATH "$ENV{SGX_SDK}/bin/${LINUX_ARCHI_STR}/sgx_edger8r")
	set(SGX_SIGN_PATH "$ENV{SGX_SDK}/bin/${LINUX_ARCHI_STR}/sgx_sign")
endif()

get_filename_component(SGX_SDK_PATH "${SGX_SDK_PATH}" ABSOLUTE)
if(NOT EXISTS "${SGX_SDK_PATH}")
	message(FATAL_ERROR "${SGX_SDK_PATH} SGX SDK installation not found!")
else()
	get_filename_component(SGX_EDGER_PATH "${SGX_EDGER_PATH}" ABSOLUTE)
	get_filename_component(SGX_SIGN_PATH "${SGX_SIGN_PATH}" ABSOLUTE)
endif()

### END Setup options ###

### Add Sub-modules ###

###### Add from Hunter ######
hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)

###### END Add from Hunter ######

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/jsoncpp)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/Intel_SGX)

### END Add Sub-modules ###

file(GLOB_RECURSE COMMON_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.hh)

file(GLOB_RECURSE COMMON_ENCLAVE_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.hh)

file(GLOB_RECURSE LibTest_App_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.hh)

file(GLOB_RECURSE Example_App_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.hh ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.edl)

file(GLOB_RECURSE Example_Enclave_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.hh ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.edl)

### Filters ###

### End Filters ###

###########################################################
### LibTest_App
###########################################################
add_executable(LibTest_App ${LibTest_App_SOURCES}  ${COMMON_SOURCES})
target_include_directories(LibTest_App PRIVATE ${JSONCPP_INCLUDE_DIRS} PRIVATE ${INTEL_SGX_INCLUDE_DIRS})

target_link_libraries(LibTest_App 
					OpenSSL::SSL 
					OpenSSL::Crypto 
					"$<$<CONFIG:Debug>:${INTEL_SGX_DEBUG_UNTRUST_LIB}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_DEBUGSIM_UNTRUST_LIB}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_RELEASE_UNTRUST_LIB}>" 
					jsoncpp_lib_static
					"${COMMON_STANDARD_LIBRARIES}"
					)

###########################################################
### Example_Enclave
###########################################################

if(MSVC)
	set(Enclave_Filename "Example_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.signed.dll")
	set(Enclave_Libname "Example_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.dll")
else()
	set(Enclave_Filename "Example_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.signed.so")
	set(Enclave_Libname "Example_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.so")
endif()

add_library(Example_Enclave SHARED ${Example_Enclave_SOURCES} ${COMMON_ENCLAVE_SOURCES})
target_include_directories(Example_Enclave BEFORE PRIVATE ${INTEL_SGX_INCLUDE_DIRS} PRIVATE "${INTEL_SGX_INCLUDE_DIRS}/tlibc" PRIVATE "${INTEL_SGX_INCLUDE_DIRS}/libc++")

set_target_properties(Example_Enclave PROPERTIES LINK_FLAGS "${ENCLAVE_OPTIONS}")

add_custom_command(TARGET Example_Enclave
	PRE_BUILD
	COMMAND "${SGX_EDGER_PATH}"  
	--trusted "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/Enclave.edl" 
	--search-path "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave" 
	--search-path "${INTEL_SGX_INCLUDE_DIRS}"
	WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave"
)

add_custom_command(TARGET Example_Enclave
	POST_BUILD
	COMMAND "${SGX_SIGN_PATH}" sign 
	-key "${CMAKE_CURRENT_LIST_DIR}/Enclave_private.pem" 
	-enclave "${CMAKE_BINARY_DIR}/$<CONFIG>/${Enclave_Libname}" 
	-out "${CMAKE_BINARY_DIR}/${Enclave_Filename}" 
	-config "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/Enclave.config.xml"
)

target_link_libraries(Example_Enclave 
					"$<$<CONFIG:Debug>:${INTEL_SGX_DEBUG_TRUST_LIB}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_DEBUGSIM_TRUST_LIB}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_RELEASE_TRUST_LIB}>" 
					)

###########################################################
### Example_App
###########################################################
add_executable(Example_App ${Example_App_SOURCES} ${COMMON_SOURCES})
target_include_directories(Example_App PRIVATE ${JSONCPP_INCLUDE_DIRS} PRIVATE ${INTEL_SGX_INCLUDE_DIRS})

if(MSVC)
	target_compile_definitions(Example_App PRIVATE ENCLAVE_FILENAME="${Enclave_Filename}" TOKEN_FILENAME="Example_Enclave.token")
else()
	target_compile_definitions(Example_App PRIVATE ENCLAVE_FILENAME="${Enclave_Filename}" TOKEN_FILENAME="Example_Enclave.token")
endif()

add_custom_command(TARGET Example_App
	PRE_BUILD
	COMMAND "${SGX_EDGER_PATH}"  
	--untrusted "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/Enclave.edl" 
	--search-path "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave" 
	--search-path "${INTEL_SGX_INCLUDE_DIRS}"
	WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/sources/example_app"
)

target_link_libraries(Example_App 
					OpenSSL::SSL 
					OpenSSL::Crypto 
					"$<$<CONFIG:Debug>:${INTEL_SGX_DEBUG_UNTRUST_LIB}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_DEBUGSIM_UNTRUST_LIB}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_RELEASE_UNTRUST_LIB}>" 
					jsoncpp_lib_static
					"${COMMON_STANDARD_LIBRARIES}"
					)
