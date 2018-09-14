cmake_minimum_required(VERSION 3.11)

#==========================================================
#   Options for Decent Project
#==========================================================
set(INTEL_SGX_SSL_MODULE ON CACHE BOOL "Switch for SGX SSL module." FORCE)
set(HUNTER_BOOST_RUNTIME_STATIC ON CACHE BOOL "Switch for using boost runtime static linking." FORCE)
#set(DECENT_CXX_STANDARD_VER c++11 CACHE STRING "C++ standard version used by decent." FORCE)

#==========================================================
#   Setup Hunter
#==========================================================

set(gate_dir "${CMAKE_CURRENT_LIST_DIR}/hunter/gate")
set(gate_module "${gate_dir}/cmake/HunterGate.cmake")
set(HUNTER_KEEP_PACKAGE_SOURCES ON)

get_filename_component(gate_module "${gate_module}" ABSOLUTE)

if(NOT EXISTS "${gate_module}")
	message(FATAL_ERROR "${gate_module} module not found!")
endif()

message("Including HunterGate: ${gate_module}")
include("${gate_module}")

get_filename_component(HUNTER_ROOT "${CMAKE_CURRENT_LIST_DIR}/hunter" ABSOLUTE)
HunterGate(URL "x" SHA1 "xxxxxxxx" FILEPATH ${CMAKE_CURRENT_LIST_DIR}/HunterConfig.cmake)

#==========================================================
#   Start Decent Project
#==========================================================
project(decent)

#==========================================================
#   Add Hunter Libraries
#==========================================================
hunter_add_package(Boost COMPONENTS filesystem date_time)
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ${HUNTER_BOOST_RUNTIME_STATIC})
set(Boost_NO_SYSTEM_PATHS ON)
find_package(Boost CONFIG REQUIRED system filesystem date_time)

message(STATUS "")
message(STATUS "==================================================")
message(STATUS "Looking for Boost library in ${BOOST_ROOT}...")
message(STATUS "Boost found?: ${Boost_FOUND}")
message(STATUS "Boost Include Dir: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost Library Dir: ${Boost_LIBRARY_DIRS}")
message(STATUS "Boost Libraries: ${Boost_LIBRARIES}")
message(STATUS "==================================================")
message(STATUS "")

hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)

hunter_add_package(ZLIB)
find_package(ZLIB REQUIRED)

#==========================================================
#   Setup options
#==========================================================

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_STATIC_LIBS "Build static libraries" ON)
option(USE_MSVC_RUNTIME_LIBRARY_DLL OFF)
option(JSONCPP_WITH_TESTS OFF)
option(JSONCPP_WITH_POST_BUILD_UNITTEST OFF)

set(OPENSSL_USE_STATIC_LIBS TRUE)

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
	set(RELEASE_OPTIONS /MT /Ox /Oi /Ob2 /fp:fast /GL /GR- /DEDEBUG)# /DNDEBUG
	
	set(ENCLAVE_OPTIONS "/NODEFAULTLIB /NOENTRY")
	
	set(COMMON_APP_DEFINES WIN32_LEAN_AND_MEAN CURL_STATICLIB)
	set(COMMON_ENCLAVE_DEFINES ENCLAVE_CODE)
#elseif(APPLE)
#	set(COMMON_OPTIONS )
#	set(DEBUG_OPTIONS -O0 -g -DDEBUG -UNDEBUG -UEDEBUG)
#	set(RELEASE_OPTIONS -O2 -UEDEBUG -UDEBUG) #-DNDEBUG defined by default
else()
	set(COMMON_OPTIONS -std=c++11 -pthread)
	set(DEBUG_OPTIONS -O0 -g -DDEBUG -UNDEBUG -UEDEBUG)
	set(SIMULATE_OPTIONS -DSIMULATING_ENCLAVE)
	set(RELEASE_OPTIONS -O2 -UEDEBUG -UDEBUG) #-DNDEBUG defined by default
	
	set(COMMON_APP_DEFINES CURL_STATICLIB)
	set(COMMON_ENCLAVE_DEFINES ENCLAVE_CODE)
endif()

set(DEBUG_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS})
set(DEBUGSIM_OPTIONS ${COMMON_OPTIONS} ${DEBUG_OPTIONS} ${SIMULATE_OPTIONS})
set(RELEASE_OPTIONS ${COMMON_OPTIONS} ${RELEASE_OPTIONS})

add_compile_options(
	"$<$<CONFIG:Debug>:${DEBUG_OPTIONS}>"
	"$<$<CONFIG:DebugSimulation>:${DEBUGSIM_OPTIONS}>"
	"$<$<CONFIG:Release>:${RELEASE_OPTIONS}>"
)

message(STATUS "")
message(STATUS "==================================================")
message(STATUS "==> Before modification: ")
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
message(STATUS "")

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
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUGSIMULATION "${CMAKE_CXX_FLAGS_DEBUG}")
	STRING (REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
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
set_property(GLOBAL PROPERTY DEBUG_CONFIGURATIONS Debug DebugSimulation)
set(CMAKE_MAP_IMPORTED_CONFIG_DEBUGSIMULATION Debug)

message(STATUS "")
message(STATUS "==================================================")
message(STATUS "==> After modification: ")
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
message(STATUS "")

#==========================================================
#   Add submodules
#==========================================================

set(BUILD_CURL_EXE OFF CACHE BOOL "Set to ON to build CURL executable." FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Set to ON to build libcurl test libraries." FORCE)
set(CURL_STATICLIB ON CACHE BOOL "Set to ON to build libcurl with static linking." FORCE)
set(CMAKE_USE_OPENSSL ON CACHE BOOL "Set to ON to build libcurl with OpenSSL." FORCE)
option(HTTP_ONLY ON)
option(ENABLE_MANUAL OFF)


add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/jsoncpp)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/Intel_SGX)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/libs/curl)

set(CPPCODEC_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/cppcodec)
set(RAPIDJSON_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/enclaveRapidJson/include)
set(TCLAP_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/libs/tclap/include)
set(CURL_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/libs/curl/include)

set(COMMON_APP_INCLUDE_DIRS ${JSONCPP_INCLUDE_DIRS} 
							 ${INTEL_SGX_SDK_INCLUDE_PATH} 
							 ${TCLAP_INCLUDE_DIR} 
							 ${CURL_INCLUDE_DIR} 
							 ${CPPCODEC_INCLUDE_DIR} 
#							 ${Boost_INCLUDE_DIRS} 
							 )

set(COMMON_ENCLAVE_INCLUDE_DIRS ${INTEL_SGX_SDK_INCLUDE_PATH} 
							 ${INTEL_SGX_SDK_INCLUDE_PATH}/tlibc 
							 ${INTEL_SGX_SDK_INCLUDE_PATH}/${INTEL_SGX_CXXLIB_NAME} 
							 ${INTEL_SGX_SSL_INCLUDE_PATH}
							 ${CPPCODEC_INCLUDE_DIR}
							 ${RAPIDJSON_INCLUDE_DIR}
							 )

#==========================================================
#   Add files
#==========================================================

file(GLOB_RECURSE SOURCES ${CMAKE_CURRENT_LIST_DIR}/sources/*.[ch]* ${CMAKE_CURRENT_LIST_DIR}/sources/*.edl)

# Common files:
file(GLOB_RECURSE SOURCES_COMMON ${CMAKE_CURRENT_LIST_DIR}/sources/common/*.[ch]*)
file(GLOB_RECURSE SOURCES_COMMON_APP ${CMAKE_CURRENT_LIST_DIR}/sources/common_app/*.[ch]*)
file(GLOB_RECURSE SOURCES_COMMON_ENCLAVE ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.[ch]*)
file(GLOB_RECURSE SOURCES_COMMON_EDL ${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave/*.edl)

# LibTest_App Files:
set(SOURCESDIR_LibTest_App ${CMAKE_CURRENT_LIST_DIR}/sources/testLib_app)
file(GLOB_RECURSE SOURCES_LibTest_App ${SOURCESDIR_LibTest_App}/*.[ch]*)

# DecentServer Files:
set(SOURCEDIR_DecentServer_App ${CMAKE_CURRENT_LIST_DIR}/sources/DecentServer_app)
set(SOURCEDIR_DecentServer_Enclave ${CMAKE_CURRENT_LIST_DIR}/sources/DecentServer_enclave)
file(GLOB_RECURSE SOURCES_DecentServer_App ${SOURCEDIR_DecentServer_App}/*.[ch]*)
file(GLOB_RECURSE SOURCES_DecentServer_Enclave ${SOURCEDIR_DecentServer_Enclave}/*.[ch]*)
file(GLOB_RECURSE SOURCES_DecentServer_EDL ${SOURCEDIR_DecentServer_Enclave}/*.edl)

# DecentApp Files:
set(SOURCEDIR_DecentApp_App ${CMAKE_CURRENT_LIST_DIR}/sources/DecentApp_app)
set(SOURCEDIR_DecentApp_Enclave ${CMAKE_CURRENT_LIST_DIR}/sources/DecentApp_enclave)
file(GLOB_RECURSE SOURCES_DecentApp_App ${SOURCEDIR_DecentApp_App}/*.[ch]*)
file(GLOB_RECURSE SOURCES_DecentApp_Enclave ${SOURCEDIR_DecentApp_Enclave}/*.[ch]*)
file(GLOB_RECURSE SOURCES_DecentApp_EDL ${SOURCEDIR_DecentApp_Enclave}/*.edl)

#==========================================================
#   Setup filters
#==========================================================

source_group(TREE ${CMAKE_CURRENT_LIST_DIR}/sources FILES ${SOURCES})
# Common Groups
# source_group(Common FILES ${SOURCES_COMMON})
# source_group(Common_Enclave FILES ${SOURCES_COMMON_ENCLAVE})
# source_group(Common_App FILES ${SOURCES_COMMON_APP})
# source_group(Common_App\\SGXRAMessages FILES ${SOURCES_COMMON_APP_SGXRAMESSAGES})
# source_group(Common_EDLs FILES ${SOURCES_COMMON_EDL})
# # LibTest_App Groups
# source_group(LibTest_App FILES ${SOURCES_LibTest_App})
# # DecentServer Groups
# source_group(DecentServer_App FILES ${SOURCES_DecentServer_App})
# source_group(DecentServer_Enclave FILES ${SOURCES_DecentServer_Enclave})
# source_group(DecentServer_EDLs FILES ${SOURCES_DecentServer_EDL})

#==========================================================
#   G++ linking flags
#==========================================================

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
add_executable(LibTest_App ${SOURCES_COMMON} ${SOURCES_COMMON_APP} ${SOURCES_LibTest_App})
target_include_directories(LibTest_App PRIVATE ${COMMON_APP_INCLUDE_DIRS} 
							 ${SOURCESDIR_LibTest_App})

target_compile_definitions(LibTest_App PRIVATE ${COMMON_APP_DEFINES})

target_link_libraries(LibTest_App  
					${COMMON_STANDARD_LIBRARIES}
					#${Boost_LIBRARIES}
					jsoncpp_lib_static
					libcurl
					OpenSSL::SSL 
					OpenSSL::Crypto 
					Boost::filesystem
					Boost::date_time
					Boost::system
					)


if(MSVC)
	set(Enclave_Prog_Prefix )
	set(Enclave_Prog_Postfix dll)
	set(Enclave_Bin_Path "${CMAKE_BINARY_DIR}/$<CONFIG>")
else()
	set(Enclave_Prog_Prefix ${CMAKE_SHARED_LIBRARY_PREFIX})
	set(Enclave_Prog_Postfix so)
	set(Enclave_Bin_Path "${CMAKE_BINARY_DIR}")
endif()

#==========================================================
#   Enclave Projects
#==========================================================

set(Enclave_Project_List DecentServer DecentApp)

foreach(Proj_Name IN ITEMS ${Enclave_Project_List})
	
	###########################################################
	### Enclave
	###########################################################

	set(${Proj_Name}_Enclave_File "${Enclave_Prog_Prefix}${Proj_Name}_Enclave.signed.${Enclave_Prog_Postfix}")
	set(${Proj_Name}_Enclave_Lib "${Enclave_Prog_Prefix}${Proj_Name}_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.${Enclave_Prog_Postfix}")

	add_library(${Proj_Name}_Enclave SHARED ${SOURCES_COMMON} ${SOURCES_COMMON_EDL} ${SOURCES_COMMON_ENCLAVE} ${SOURCES_${Proj_Name}_Enclave} ${SOURCES_${Proj_Name}_EDL})

	target_compile_definitions(${Proj_Name}_Enclave PRIVATE ${COMMON_ENCLAVE_DEFINES})

	target_include_directories(${Proj_Name}_Enclave BEFORE PRIVATE ${COMMON_ENCLAVE_INCLUDE_DIRS} 
								 ${SOURCEDIR_${Proj_Name}_Enclave})

	set_target_properties(${Proj_Name}_Enclave PROPERTIES LINK_FLAGS "${ENCLAVE_OPTIONS}")

	add_custom_command(TARGET ${Proj_Name}_Enclave
		PRE_BUILD
		COMMAND "${INTEL_SGX_EDGER_PATH}"  
		--trusted "${SOURCEDIR_${Proj_Name}_Enclave}/Enclave.edl" 
		--search-path "${SOURCEDIR_${Proj_Name}_Enclave}" 
		--search-path "${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave" 
		--search-path "${INTEL_SGX_SDK_INCLUDE_PATH}"
		--search-path "${INTEL_SGX_SSL_INCLUDE_PATH}"
		WORKING_DIRECTORY "${SOURCEDIR_${Proj_Name}_Enclave}"
	)

	add_custom_command(TARGET ${Proj_Name}_Enclave
		POST_BUILD
		COMMAND "${INTEL_SGX_SIGNER_PATH}" sign 
		-key "${CMAKE_CURRENT_LIST_DIR}/Enclave_private.pem" 
		-enclave "${Enclave_Bin_Path}/${${Proj_Name}_Enclave_Lib}" 
		-out "${CMAKE_BINARY_DIR}/${${Proj_Name}_Enclave_File}" 
		-config "${SOURCEDIR_${Proj_Name}_Enclave}/Enclave.config.xml"
	)

	target_link_libraries(${Proj_Name}_Enclave 
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
	### App
	###########################################################

	add_executable(${Proj_Name}_App ${SOURCES_COMMON} ${SOURCES_COMMON_EDL} ${SOURCES_COMMON_APP} ${SOURCES_${Proj_Name}_App} ${SOURCES_${Proj_Name}_EDL})
	target_include_directories(${Proj_Name}_App 
								PRIVATE ${COMMON_APP_INCLUDE_DIRS} 
								 ${SOURCEDIR_${Proj_Name}_App})

	target_compile_definitions(${Proj_Name}_App PRIVATE ${COMMON_APP_DEFINES} ENCLAVE_FILENAME="${${Proj_Name}_Enclave_File}" TOKEN_FILENAME="${Proj_Name}_Enclave.token")

	add_custom_command(TARGET ${Proj_Name}_App
		PRE_BUILD
		COMMAND "${INTEL_SGX_EDGER_PATH}"  
		--untrusted "${SOURCEDIR_${Proj_Name}_Enclave}/Enclave.edl" 
		--search-path "${SOURCEDIR_${Proj_Name}_Enclave}" 
		--search-path "${CMAKE_CURRENT_LIST_DIR}/sources/common_enclave" 
		--search-path "${INTEL_SGX_SDK_INCLUDE_PATH}"
		--search-path "${INTEL_SGX_SSL_INCLUDE_PATH}"
		WORKING_DIRECTORY "${SOURCEDIR_${Proj_Name}_App}"
	)

	target_link_libraries(${Proj_Name}_App 
						"$<$<CONFIG:Debug>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG}>" 
						"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM}>" 
						"$<$<CONFIG:Release>:${INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE}>" 
						"$<$<CONFIG:Debug>:${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUG}>" 
						"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SSL_LIB_UNTRUSTED_DEBUGSIM}>" 
						"$<$<CONFIG:Release>:${INTEL_SGX_SSL_LIB_UNTRUSTED_RELEASE}>"
						${COMMON_STANDARD_LIBRARIES}
						jsoncpp_lib_static
						libcurl
						OpenSSL::SSL 
						OpenSSL::Crypto 
						Boost::filesystem
						Boost::date_time
						Boost::system
					)
	
	### Config Flags for Linux OS ###
	if(NOT MSVC)

		target_compile_options(${Proj_Name}_Enclave
							PRIVATE ${INTEL_SGX_SDK_C_FLAGS} $<$<COMPILE_LANGUAGE:CXX>:${INTEL_SGX_SDK_CXX_FLAGS}>
							)

		set_target_properties(${Proj_Name}_Enclave 
							PROPERTIES 
							LINK_FLAGS_DEBUG "${INTEL_SGX_SDK_LINKER_FLAGS_T_HW}"
							LINK_FLAGS_DEBUGSIMULATION "${INTEL_SGX_SDK_LINKER_FLAGS_T_SIM}"
							LINK_FLAGS_RELEASE "${INTEL_SGX_SDK_LINKER_FLAGS_T_HW}"
							)

		set_target_properties(${Proj_Name}_App 
							PROPERTIES 
							LINK_FLAGS_DEBUG "${INTEL_SGX_SDK_LINKER_FLAGS_U_HW}"
							LINK_FLAGS_DEBUGSIMULATION "${INTEL_SGX_SDK_LINKER_FLAGS_U_SIM}"
							LINK_FLAGS_RELEASE "${INTEL_SGX_SDK_LINKER_FLAGS_U_HW}"
							)

	endif()
	
endforeach()

