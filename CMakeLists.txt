cmake_minimum_required(VERSION 3.11)

project(decent)

set(INTEL_SGX_SSL_MODULE ON CACHE BOOL "Switch for SGX SSL module" FORCE)
#Add any required boost libraries here:
set(BOOST_Req_Libs filesystem date_time)

### Setup and find boost ###

set(BOOST_ROOT "${CMAKE_CURRENT_BINARY_DIR}/libs/boost")
set(BOOST_LIBRARYDIR "${BOOST_ROOT}/lib")

set(Boost_LIBRARY_DIR_RELEASE "${BOOST_ROOT}/lib")
set(Boost_LIBRARY_DIR_DEBUG "${BOOST_ROOT}/lib")
set(Boost_LIBRARY_DIR "${BOOST_ROOT}/lib")
#set(Boost_DEBUG ON)
#set(Boost_DETAILED_FAILURE_MSG ON)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)
set(Boost_NO_SYSTEM_PATHS ON)
if(MSVC)
	set(Boost_COMPILER -vc141)
endif()

if(NOT EXISTS ${BOOST_ROOT})
	file(MAKE_DIRECTORY ${BOOST_ROOT})
endif()

find_package(Boost 1.66.0 COMPONENTS ${BOOST_Req_Libs})

if(NOT Boost_FOUND)
	if(MSVC)
		foreach(lib_name IN LISTS BOOST_Req_Libs)
			set(BOOST_BUILD_LIB_LIST ${BOOST_BUILD_LIB_LIST} --with-${lib_name})
		endforeach()
		set(BOOST_UPDATE_COMMAND "")
		set(BOOST_CONFIGURE_COMMAND bootstrap.bat)
		set(BOOST_BUILD_COMMAND b2 toolset=msvc-14.1 address-model=64 architecture=x86 link=static runtime-link=static install --prefix=${BOOST_ROOT} ${BOOST_BUILD_LIB_LIST})
		set(BOOST_INSTALL_COMMAND "")
	else()
		foreach(lib_name IN LISTS BOOST_Req_Libs)
			if(NOT DEFINED BOOST_BUILD_LIB_LIST)
				set(BOOST_BUILD_LIB_LIST ${lib_name})
			else()
				set(BOOST_BUILD_LIB_LIST ${BOOST_BUILD_LIB_LIST},${lib_name})
			endif()
		endforeach()
		set(BOOST_UPDATE_COMMAND "")
		set(BOOST_CONFIGURE_COMMAND ./bootstrap.sh --prefix=${BOOST_ROOT} --with-libraries=${BOOST_BUILD_LIB_LIST})
		set(BOOST_BUILD_COMMAND ./bjam install)
		set(BOOST_INSTALL_COMMAND "")
	endif()

	message(STATUS "==================================================")
	message(STATUS "Building Boost...")
	message(STATUS "${BOOST_CONFIGURE_COMMAND}")
	execute_process(COMMAND ${BOOST_CONFIGURE_COMMAND}
					WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/libs/boost
					OUTPUT_FILE "${BOOST_ROOT}/build_output1.txt"
					)

	message(STATUS "${BOOST_BUILD_COMMAND}")
	execute_process(COMMAND ${BOOST_BUILD_COMMAND}
					WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/libs/boost
					OUTPUT_FILE "${BOOST_ROOT}/build_output2.txt"
					)
	message(STATUS "Build completed. Build log can be found at ${BOOST_ROOT}/build_output.txt")
	message(STATUS "==================================================")
endif()

message(STATUS "==================================================")
message(STATUS "Looking for Boost library in ${BOOST_ROOT}...")
find_package(Boost 1.66.0 COMPONENTS ${BOOST_Req_Libs} REQUIRED)
message(STATUS "Boost found?: ${Boost_FOUND}")
message(STATUS "Boost Include Dir: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost Library Dir: ${Boost_LIBRARY_DIRS}")
message(STATUS "Boost Libraries: ${Boost_LIBRARIES}")
message(STATUS "==================================================")

### End Setup and find boost ###

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
#elseif(APPLE)
#	set(COMMON_OPTIONS )
#	set(DEBUG_OPTIONS -O0 -g -DDEBUG -UNDEBUG -UEDEBUG)
#	set(RELEASE_OPTIONS -O2 -UEDEBUG -UDEBUG) #-DNDEBUG defined by default
else()
	set(COMMON_OPTIONS )
	set(DEBUG_OPTIONS -O0 -g -DDEBUG -UNDEBUG -UEDEBUG)
	set(RELEASE_OPTIONS -O2 -UEDEBUG -UDEBUG) #-DNDEBUG defined by default
endif()

set(DEBUG_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS})
set(DEBUGSIM_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS})
set(RELEASE_OPTIONS ${COMMON_OPTIONS} ${RELEASE_OPTIONS})

add_compile_options(
	"$<$<CONFIG:Debug>:${DEBUG_OPTIONS}>"
	"$<$<CONFIG:DebugSimulation>:${DEBUGSIM_OPTIONS}>"
	"$<$<CONFIG:Release>:${RELEASE_OPTIONS}>"
)

if(UNIX)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread")
endif()

message(STATUS "==================================================")
message(STATUS "CMake Standard Libraries:")
message(STATUS "${CMAKE_CXX_STANDARD_LIBRARIES_INIT}")
message(STATUS "CMake CXX Flags (Debug):")
message(STATUS "${CMAKE_CXX_FLAGS_DEBUG}")
message(STATUS "CMake CXX Flags (Release):")
message(STATUS "${CMAKE_CXX_FLAGS_RELEASE}")
message(STATUS "CMake CXX Link Flags (Debug):")
message(STATUS "${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
message(STATUS "CMake CXX Link Flags (Release):")
message(STATUS "${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
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

set(CMAKE_CXX_FLAGS_DEBUGSIMULATION ${CMAKE_CXX_FLAGS_DEBUG})
set(CMAKE_C_FLAGS_DEBUGSIMULATION ${CMAKE_C_FLAGS_DEBUG})
set(CMAKE_EXE_LINKER_FLAGS_DEBUGSIMULATION ${CMAKE_EXE_LINKER_FLAGS_DEBUG})
set(CMAKE_SHARED_LINKER_FLAGS_DEBUGSIMULATION ${CMAKE_SHARED_LINKER_FLAGS_DEBUG})

set(CMAKE_CONFIGURATION_TYPES Release Debug DebugSimulation)

### END Setup options ###

### Add Sub-modules ###

###### Add from Hunter ######
#hunter_add_package(OpenSSL)
#find_package(OpenSSL REQUIRED)

###### END Add from Hunter ######

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/jsoncpp)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/Intel_SGX)

set(CPPCODEC_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/cppcodec)

### END Add Sub-modules ###

file(GLOB_RECURSE COMMON_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.hh)

file(GLOB_RECURSE COMMON_APP_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/common_app/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/common_app/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/common_app/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/common_app/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/common_app/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/common_app/*.hh)

file(GLOB_RECURSE COMMON_ENCLAVE_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.hh)

file(GLOB_RECURSE COMMON_EDL_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.edl)

file(GLOB_RECURSE LibTest_App_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app/*.hh)

file(GLOB_RECURSE Example_App_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/example_app/*.hh ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.edl)

file(GLOB_RECURSE Example_Enclave_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.c ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.cpp ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.cc ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.h ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.hpp ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.hh ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.edl)

file(GLOB_RECURSE Example_EDL_SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/*.edl)


### Library link flags ###
if(MSVC)
	set(WHOLE_ARCHIVE_FLAG_BEGIN "")
	set(WHOLE_ARCHIVE_FLAG_END "")
	set(GROUP_FLAG_BEGIN "")
	set(GROUP_FLAG_END "")
else()
	set(WHOLE_ARCHIVE_FLAG_BEGIN -Wl,--whole-archive)
	set(WHOLE_ARCHIVE_FLAG_END -Wl,--no-whole-archive)
	set(GROUP_FLAG_BEGIN -Wl,--start-group)
	set(GROUP_FLAG_END -Wl,--end-group)
endif()

###########################################################
### LibTest_App
###########################################################
add_executable(LibTest_App ${LibTest_App_SOURCES} ${COMMON_APP_SOURCES} ${COMMON_SOURCES})
target_include_directories(LibTest_App PRIVATE ${JSONCPP_INCLUDE_DIRS} PRIVATE ${INTEL_SGX_SDK_INCLUDE_PATH} PRIVATE ${Boost_INCLUDE_DIRS})

target_link_libraries(LibTest_App 
#					OpenSSL::SSL 
#					OpenSSL::Crypto 
					"$<$<CONFIG:Debug>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE}>" 
					"$<$<CONFIG:Debug>:${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUG}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUGSIM}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_SSL_LIB_UNTRUSTED_RELEASE}>" 
					jsoncpp_lib_static
					${COMMON_STANDARD_LIBRARIES}
					${Boost_LIBRARIES}
					)

###########################################################
### Example_Enclave
###########################################################

### Filters ###
source_group("" FILES ${Example_Enclave_SOURCES} ${COMMON_ENCLAVE_SOURCES} ${COMMON_SOURCES} ${Example_EDL_SOURCES} ${COMMON_EDL_SOURCES})

source_group(Common FILES ${COMMON_SOURCES})
source_group(Common_Enclave FILES ${COMMON_ENCLAVE_SOURCES})

source_group(Example_Enclave FILES ${Example_Enclave_SOURCES})

source_group(EDLs FILES ${Example_EDL_SOURCES})
source_group(Common_EDLs FILES ${COMMON_EDL_SOURCES})
### End Filters ###

if(MSVC)
	set(Enclave_Filename "Example_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.signed.dll")
	set(Enclave_Libname "Example_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.dll")
	set(Enclave_Bin_Path "${CMAKE_BINARY_DIR}/$<CONFIG>")
else()
	set(Enclave_Filename "${CMAKE_SHARED_LIBRARY_PREFIX}Example_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.signed.so")
	set(Enclave_Libname "${CMAKE_SHARED_LIBRARY_PREFIX}Example_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.so")
	set(Enclave_Bin_Path "${CMAKE_BINARY_DIR}")
endif()

add_library(Example_Enclave SHARED ${Example_Enclave_SOURCES} ${COMMON_ENCLAVE_SOURCES} ${COMMON_SOURCES})

target_include_directories(Example_Enclave BEFORE 
							PRIVATE ${INTEL_SGX_SDK_INCLUDE_PATH} 
							PRIVATE "${INTEL_SGX_SDK_INCLUDE_PATH}/tlibc" 
							PRIVATE "${INTEL_SGX_SDK_INCLUDE_PATH}/${INTEL_SGX_CXXLIB_NAME}" 
							PRIVATE ${INTEL_SGX_SSL_INCLUDE_PATH}
							PRIVATE ${CPPCODEC_INCLUDE_DIR}
							)

set_target_properties(Example_Enclave PROPERTIES LINK_FLAGS "${ENCLAVE_OPTIONS}")

add_custom_command(TARGET Example_Enclave
	PRE_BUILD
	COMMAND "${INTEL_SGX_EDGER_PATH}"  
	--trusted "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/Enclave.edl" 
	--search-path "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave" 
	--search-path "${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave" 
	--search-path "${INTEL_SGX_SDK_INCLUDE_PATH}"
	--search-path "${INTEL_SGX_SSL_INCLUDE_PATH}"
	WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave"
)

add_custom_command(TARGET Example_Enclave
	POST_BUILD
	COMMAND "${INTEL_SGX_SIGNER_PATH}" sign 
	-key "${CMAKE_CURRENT_LIST_DIR}/Enclave_private.pem" 
	-enclave "${Enclave_Bin_Path}/${Enclave_Libname}" 
	-out "${CMAKE_BINARY_DIR}/${Enclave_Filename}" 
	-config "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/Enclave.config.xml"
)

target_link_libraries(Example_Enclave 
					${WHOLE_ARCHIVE_FLAG_BEGIN} 
					"$<$<CONFIG:Debug>:${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE}>" 
					"$<$<CONFIG:Debug>:${INTEL_SGX_SSL_LIB_WHOLE_ARC_DEBUG}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SSL_LIB_WHOLE_ARC_DEBUGSIM}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_SSL_LIB_WHOLE_ARC_RELEASE}>" 
					${WHOLE_ARCHIVE_FLAG_END}
					${GROUP_FLAG_BEGIN}
					"$<$<CONFIG:Debug>:${INTEL_SGX_SDK_LIB_GROUP_DEBUG}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SDK_LIB_GROUP_DEBUGSIM}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_SDK_LIB_GROUP_RELEASE}>" 
					"$<$<CONFIG:Debug>:${INTEL_SGX_SSL_LIB_GROUP_DEBUG}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SSL_LIB_GROUP_DEBUGSIM}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_SSL_LIB_GROUP_RELEASE}>" 
					${GROUP_FLAG_END}
					)

###########################################################
### Example_App
###########################################################

### Filters ###
source_group("" FILES ${Example_App_SOURCES} ${COMMON_APP_SOURCES} ${COMMON_SOURCES} ${Example_EDL_SOURCES} ${COMMON_EDL_SOURCES})

source_group(Common FILES ${COMMON_SOURCES})
source_group(Common_App FILES ${COMMON_APP_SOURCES})

source_group(Example_App FILES ${Example_App_SOURCES})

source_group(EDLs FILES ${Example_EDL_SOURCES})
source_group(Common_EDLs FILES ${COMMON_EDL_SOURCES})
### End Filters ###

add_executable(Example_App ${Example_App_SOURCES} ${COMMON_APP_SOURCES} ${COMMON_SOURCES})
target_include_directories(Example_App PRIVATE ${JSONCPP_INCLUDE_DIRS} PRIVATE ${INTEL_SGX_SDK_INCLUDE_PATH} PRIVATE ${Boost_INCLUDE_DIRS})

if(MSVC)
	target_compile_definitions(Example_App PRIVATE ENCLAVE_FILENAME="${Enclave_Filename}" TOKEN_FILENAME="Example_Enclave.token")
else()
	target_compile_definitions(Example_App PRIVATE ENCLAVE_FILENAME="${Enclave_Filename}" TOKEN_FILENAME="Example_Enclave.token")
endif()

add_custom_command(TARGET Example_App
	PRE_BUILD
	COMMAND "${INTEL_SGX_EDGER_PATH}"  
	--untrusted "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave/Enclave.edl" 
	--search-path "${CMAKE_CURRENT_LIST_DIR}/sources/example_enclave" 
	--search-path "${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave" 
	--search-path "${INTEL_SGX_SDK_INCLUDE_PATH}"
	--search-path "${INTEL_SGX_SSL_INCLUDE_PATH}"
	WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/sources/example_app"
)

target_link_libraries(Example_App 
#					OpenSSL::SSL 
#					OpenSSL::Crypto 
					"$<$<CONFIG:Debug>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE}>" 
					"$<$<CONFIG:Debug>:${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUG}>" 
					"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUGSIM}>" 
					"$<$<CONFIG:Release>:${INTEL_SGX_SSL_LIB_UNTRUSTED_RELEASE}>"
					${json_LIB}
					${COMMON_STANDARD_LIBRARIES}
					${Boost_LIBRARIES}
				)


### Config Flags for Linux OS ###

if(NOT MSVC)
target_compile_options(Example_Enclave
					PRIVATE ${INTEL_SGX_SDK_C_FLAGS} $<$<COMPILE_LANGUAGE:CXX>:${INTEL_SGX_SDK_CXX_FLAGS}>
					)

set_target_properties(Example_Enclave 
					PROPERTIES 
					LINK_FLAGS_DEBUG "${INTEL_SGX_SDK_LINKER_FLAGS_T_HW}"
					LINK_FLAGS_DEBUGSIMULATION "${INTEL_SGX_SDK_LINKER_FLAGS_T_SIM}"
					LINK_FLAGS_RELEASE "${INTEL_SGX_SDK_LINKER_FLAGS_T_HW}"
					)

set_target_properties(Example_App 
					PROPERTIES 
					LINK_FLAGS_DEBUG "${INTEL_SGX_SDK_LINKER_FLAGS_U_HW}"
					LINK_FLAGS_DEBUGSIMULATION "${INTEL_SGX_SDK_LINKER_FLAGS_U_SIM}"
					LINK_FLAGS_RELEASE "${INTEL_SGX_SDK_LINKER_FLAGS_U_HW}"
					)

endif()

### End Config Flags for Linux OS ###

