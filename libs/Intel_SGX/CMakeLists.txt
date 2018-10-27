cmake_minimum_required(VERSION 3.0)

#project(Intel_SGX_SDK)

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
	set(WIN_ARCHI_STR "win32")
	set(LINUX_LIB_ARCHI_STR "lib") #for libs
	set(LINUX_BIN_ARCHI_STR "x86") #for bins, e.g. signing tool.
else()
	set(WIN_ARCHI_STR "x64")
	set(LINUX_LIB_ARCHI_STR "lib64") #for libs
	set(LINUX_BIN_ARCHI_STR "x64") #for bins, e.g. signing tool.
endif()

############################
# SGX SDK Path
############################
If(WIN32) #Windows
	if((NOT DEFINED ENV{SGXSDKInstallPath}) OR (NOT EXISTS "$ENV{SGXSDKInstallPath}"))
		message(FATAL_ERROR "Intel SGX SDK is not installed properly!")
	else()
		get_filename_component(INTEL_SGX_SDK_PATH "$ENV{SGXSDKInstallPath}" ABSOLUTE)
	endif()
elseif(UNIX) ####UNIX
	if(APPLE) #APPLE probably is not supported
		message(WARNING "MacOS may need different configuration for Intel SGX")
	endif()
	
	if((NOT DEFINED ENV{SGX_SDK}))
		set(INTEL_SGX_SDK_PATH "/opt/intel/sgxsdk")
	else()
		set(INTEL_SGX_SDK_PATH "$ENV{SGX_SDK}")
	endif()
	
	if(NOT EXISTS ${INTEL_SGX_SDK_PATH})
		message(FATAL_ERROR "Intel SGX SDK is not installed properly!")
	else()
		get_filename_component(INTEL_SGX_SDK_PATH "${INTEL_SGX_SDK_PATH}" ABSOLUTE)
	endif()
else()
	message(FATAL_ERROR "OS not supported by Intel SGX!")
endif()

############################
# SGX Tools Path
############################
if(MSVC)
	set(INTEL_SGX_EDGER_PATH "${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_edger8r.exe")
	set(INTEL_SGX_SIGNER_PATH "${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_sign.exe")
elseif(APPLE)
	set(INTEL_SGX_EDGER_PATH "${INTEL_SGX_SDK_PATH}/bin/${LINUX_BIN_ARCHI_STR}/sgx_edger8r")
	set(INTEL_SGX_SIGNER_PATH "${INTEL_SGX_SDK_PATH}/bin/${LINUX_BIN_ARCHI_STR}/sgx_sign")
else()
	set(INTEL_SGX_EDGER_PATH "${INTEL_SGX_SDK_PATH}/bin/${LINUX_BIN_ARCHI_STR}/sgx_edger8r")
	set(INTEL_SGX_SIGNER_PATH "${INTEL_SGX_SDK_PATH}/bin/${LINUX_BIN_ARCHI_STR}/sgx_sign")
endif()

get_filename_component(INTEL_SGX_EDGER_PATH ${INTEL_SGX_EDGER_PATH} ABSOLUTE)
get_filename_component(INTEL_SGX_SIGNER_PATH ${INTEL_SGX_SIGNER_PATH} ABSOLUTE)

############################
# SGX Lib Path
############################
if(WIN32)
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE ${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_trts.lib)
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG ${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_trts.lib)
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM ${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_trts_sim.lib)
	
	file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE 
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_uae_service.lib
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_ukey_exchange.lib
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_urts.lib)
	
	file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG 
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_uae_service.lib
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_ukey_exchange.lib
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_urts.lib)
	
	file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM 
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_uae_service_sim.lib
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_ukey_exchange.lib
				${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_urts_sim.lib)
	
	if(NOT TARGET IntelSGX::SDK_Trusted_service)
		add_library(IntelSGX::SDK_Trusted_service STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_service PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Trusted_service PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tservice.lib"
			IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tservice.lib"
			IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tservice.lib"
			IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tservice_sim.lib"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_stdc)
		add_library(IntelSGX::SDK_Trusted_stdc STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_stdc PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation
			INTERFACE_INCLUDE_DIRECTORIES "${INTEL_SGX_SDK_PATH}/include/tlibc")
		set_target_properties(IntelSGX::SDK_Trusted_stdc PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tstdc.lib"
			IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tstdc.lib"
			IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tstdc.lib"
			IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tstdc.lib"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_cxx)
		add_library(IntelSGX::SDK_Trusted_cxx STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_cxx PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation
			INTERFACE_INCLUDE_DIRECTORIES "${INTEL_SGX_SDK_PATH}/include/libc++")
		set_target_properties(IntelSGX::SDK_Trusted_cxx PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tcxx.lib"
			IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcxx.lib"
			IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tcxx.lib"
			IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcxx.lib"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_key_exchange)
		add_library(IntelSGX::SDK_Trusted_key_exchange STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_key_exchange PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Trusted_key_exchange PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tkey_exchange.lib"
			IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tkey_exchange.lib"
			IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tkey_exchange.lib"
			IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tkey_exchange.lib"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_crypto)
		add_library(IntelSGX::SDK_Trusted_crypto STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_crypto PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Trusted_crypto PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tcrypto.lib"
			IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcrypto.lib"
			IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tcrypto.lib"
			IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcrypto.lib"
		)
	endif()
	
	#C Flags:
	set(INTEL_SGX_SDK_C_FLAGS )
	#CXX Flags:
	set(INTEL_SGX_SDK_CXX_FLAGS )
	
	#Linker Flags (Trusted):
	set(INTEL_SGX_SDK_LINKER_FLAGS_T )
	
	#Linker Flags (Untrusted):
	set(INTEL_SGX_SDK_LINKER_FLAGS_U )
elseif(UNIX)
	
	#set(INTEL_SGX_SDK_LIB_PATH "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}")
	
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_trts.a)
	
	file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_ukey_exchange.a)
				
	list(APPEND INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE "sgx_uae_service")
	list(APPEND INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE "sgx_urts")
	
	
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_trts.a)
	
	file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_ukey_exchange.a)
				
	list(APPEND INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG "sgx_uae_service")
	list(APPEND INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG "sgx_urts")
	
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_trts_sim.a)
	
	file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_ukey_exchange.a
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_uae_service_sim.so
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_urts_sim.so)

	if(NOT TARGET IntelSGX::SDK_Trusted_service)
		add_library(IntelSGX::SDK_Trusted_service STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_service PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Trusted_service PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tservice.a"
			IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tservice.a"
			IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tservice.a"
			IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tservice_sim.a"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_stdc)
		add_library(IntelSGX::SDK_Trusted_stdc STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_stdc PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation
			INTERFACE_INCLUDE_DIRECTORIES "${INTEL_SGX_SDK_PATH}/include/tlibc")
		set_target_properties(IntelSGX::SDK_Trusted_stdc PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tstdc.a"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_cxx)
		add_library(IntelSGX::SDK_Trusted_cxx STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_cxx PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation
			INTERFACE_INCLUDE_DIRECTORIES "${INTEL_SGX_SDK_PATH}/include/libcxx")
		set_target_properties(IntelSGX::SDK_Trusted_cxx PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tcxx.a"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_key_exchange)
		add_library(IntelSGX::SDK_Trusted_key_exchange STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_key_exchange PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Trusted_key_exchange PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tkey_exchange.a"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_crypto)
		add_library(IntelSGX::SDK_Trusted_crypto STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_crypto PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Trusted_crypto PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tcrypto.a"
		)
	endif()
	
	#C Flags:
	set(INTEL_SGX_SDK_C_FLAGS -nostdinc -fvisibility=hidden -fpie -fstack-protector)
	#CXX Flags:
	set(INTEL_SGX_SDK_CXX_FLAGS -nostdinc++ -std=c++11)
	
	#Linker Flags (Trusted):
	set(INTEL_SGX_SDK_LINKER_FLAGS_T "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0")
	
endif()

############################
# SGX VARIABLES TO BE EXPORTED
############################
# ${INTEL_SGX_SDK_PATH}
# ${INTEL_SGX_SDK_INCLUDE_PATH}

# ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG}
# ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM}
# ${INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE}

# ${INTEL_SGX_SDK_LIB_GROUP_DEBUG}
# ${INTEL_SGX_SDK_LIB_GROUP_DEBUGSIM}
# ${INTEL_SGX_SDK_LIB_GROUP_RELEASE}

# ${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG}
# ${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM}
# ${INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE}

# ${INTEL_SGX_SDK_C_FLAGS}
# ${INTEL_SGX_SDK_CXX_FLAGS}
# ${INTEL_SGX_SDK_LINKER_FLAGS_T}
# ${INTEL_SGX_SDK_LINKER_FLAGS_U}

# ${INTEL_SGX_EDGER_PATH}
# ${INTEL_SGX_SIGNER_PATH}
# ${INTEL_SGX_CXXLIB_NAME}

set(INTEL_SGX_SDK_INCLUDE_DIR "${INTEL_SGX_SDK_PATH}/include")

list(APPEND INTEL_SGX_SDK_C_INCLUDE_DIR "${INTEL_SGX_SDK_PATH}/include/tlibc")
list(APPEND INTEL_SGX_SDK_C_INCLUDE_DIR "${INTEL_SGX_SDK_PATH}/include/${INTEL_SGX_CXXLIB_NAME}")

if(NOT TARGET IntelSGX::SDK_Trusted_Whole_lib)
	add_library(IntelSGX::SDK_Trusted_Whole_lib STATIC IMPORTED GLOBAL)
	set_target_properties(IntelSGX::SDK_Trusted_Whole_lib PROPERTIES IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
	set_target_properties(IntelSGX::SDK_Trusted_Whole_lib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${INTEL_SGX_SDK_INCLUDE_DIR}")
	set_target_properties(IntelSGX::SDK_Trusted_Whole_lib PROPERTIES 
		#IMPORTED_LOCATION ${INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE}
		IMPORTED_LOCATION_DEBUG ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG}
		IMPORTED_LOCATION_RELEASE ${INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE}
		IMPORTED_LOCATION_DEBUGSIMULATION ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM})
endif()

if(NOT TARGET IntelSGX::SDK_Untrusted)
	add_library(IntelSGX::SDK_Untrusted INTERFACE IMPORTED GLOBAL)
	set_target_properties(IntelSGX::SDK_Untrusted PROPERTIES 
		INTERFACE_INCLUDE_DIRECTORIES "${INTEL_SGX_SDK_INCLUDE_DIR}"
	)
	set_target_properties(IntelSGX::SDK_Untrusted PROPERTIES 
		INTERFACE_LINK_LIBRARIES 
		"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM}>$<$<AND:$<CONFIG:Debug>,$<NOT:$<CONFIG:DebugSimulation>>>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG}>$<$<CONFIG:Release>:${INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE}>" 
		#INTERFACE_LINK_OPTIONS ""
	)
endif()

set(INTEL_SGX_SDK_PATH ${INTEL_SGX_SDK_PATH} PARENT_SCOPE)
set(INTEL_SGX_SDK_INCLUDE_PATH "${INTEL_SGX_SDK_PATH}/include" PARENT_SCOPE)

set(INTEL_SGX_EDGER_PATH ${INTEL_SGX_EDGER_PATH} PARENT_SCOPE)
set(INTEL_SGX_SIGNER_PATH ${INTEL_SGX_SIGNER_PATH} PARENT_SCOPE)

#set(INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG} PARENT_SCOPE)
#set(INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM} PARENT_SCOPE)
#set(INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE ${INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE} PARENT_SCOPE)

#set(INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG ${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG} PARENT_SCOPE)
#set(INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM ${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM} PARENT_SCOPE)
#set(INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE ${INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE} PARENT_SCOPE)

set(INTEL_SGX_SDK_C_FLAGS ${INTEL_SGX_SDK_C_FLAGS} PARENT_SCOPE)
set(INTEL_SGX_SDK_CXX_FLAGS ${INTEL_SGX_SDK_CXX_FLAGS} PARENT_SCOPE)
set(INTEL_SGX_SDK_LINKER_FLAGS_T ${INTEL_SGX_SDK_LINKER_FLAGS_T} PARENT_SCOPE)
