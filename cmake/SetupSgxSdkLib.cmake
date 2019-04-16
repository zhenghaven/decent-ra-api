cmake_minimum_required(VERSION 3.0)

message(STATUS "")
message(STATUS "Adding Intel SGX Targets...")

include(${CMAKE_CURRENT_LIST_DIR}/FindSgxSdk.cmake)

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
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		target_include_directories(IntelSGX::SDK_Trusted_stdc BEFORE INTERFACE ${INTEL_SGX_SDK_INCLUDE_DIR}/tlibc)
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
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		target_include_directories(IntelSGX::SDK_Trusted_cxx BEFORE INTERFACE ${INTEL_SGX_SDK_INCLUDE_DIR}/libc++)
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
	if(NOT TARGET IntelSGX::SDK_Trusted_file_system)
		add_library(IntelSGX::SDK_Trusted_file_system STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_file_system PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Trusted_file_system PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tprotected_fs.lib"
			IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tprotected_fs.lib"
			IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tprotected_fs.lib"
			IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tprotected_fs.lib"
		)
	endif()
	if(NOT TARGET IntelSGX::Trusted::switchless)
		add_library(IntelSGX::Trusted::switchless STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::Trusted::switchless PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		#set_target_properties(IntelSGX::Trusted::switchless PROPERTIES 
		#	IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tswitchless.lib"
		#	IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tswitchless.lib"
		#	IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tswitchless.lib"
		#	IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tswitchless.lib"
		#)
	endif()
	if(NOT TARGET IntelSGX::SDK_Untrusted_file_system)
		add_library(IntelSGX::SDK_Untrusted_file_system STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Untrusted_file_system PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Untrusted_file_system PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_uprotected_fs.lib"
			IMPORTED_LOCATION_DEBUG           "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_uprotected_fs.lib"
			IMPORTED_LOCATION_RELEASE         "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_uprotected_fs.lib"
			IMPORTED_LOCATION_DEBUGSIMULATION "${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_uprotected_fs.lib"
		)
	endif()
	
elseif(UNIX)
	
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
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		target_include_directories(IntelSGX::SDK_Trusted_stdc BEFORE INTERFACE ${INTEL_SGX_SDK_INCLUDE_DIR}/tlibc)
		set_target_properties(IntelSGX::SDK_Trusted_stdc PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tstdc.a"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Trusted_cxx)
		add_library(IntelSGX::SDK_Trusted_cxx STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_cxx PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		target_include_directories(IntelSGX::SDK_Trusted_cxx BEFORE INTERFACE ${INTEL_SGX_SDK_INCLUDE_DIR}/libcxx)
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
	if(NOT TARGET IntelSGX::SDK_Trusted_file_system)
		add_library(IntelSGX::SDK_Trusted_file_system STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Trusted_file_system PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Trusted_file_system PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tprotected_fs.a"
		)
	endif()
	if(NOT TARGET IntelSGX::Trusted::switchless)
		add_library(IntelSGX::Trusted::switchless STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::Trusted::switchless PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::Trusted::switchless PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tswitchless.a"
		)
	endif()
	if(NOT TARGET IntelSGX::SDK_Untrusted_file_system)
		add_library(IntelSGX::SDK_Untrusted_file_system STATIC IMPORTED GLOBAL)
		set_target_properties(IntelSGX::SDK_Untrusted_file_system PROPERTIES 
			IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
		set_target_properties(IntelSGX::SDK_Untrusted_file_system PROPERTIES 
			IMPORTED_LOCATION                 "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_uprotected_fs.a"
		)
	endif()
	
endif()

if(NOT TARGET IntelSGX::SDK_Trusted_Whole_lib)
	add_library(IntelSGX::SDK_Trusted_Whole_lib STATIC IMPORTED GLOBAL)
	set_target_properties(IntelSGX::SDK_Trusted_Whole_lib PROPERTIES IMPORTED_CONFIGURATIONS Release Debug DebugSimulation)
	set_target_properties(IntelSGX::SDK_Trusted_Whole_lib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${INTEL_SGX_SDK_INCLUDE_DIR})
	set_target_properties(IntelSGX::SDK_Trusted_Whole_lib PROPERTIES 
		IMPORTED_LOCATION_DEBUG ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG}
		IMPORTED_LOCATION_RELEASE ${INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE}
		IMPORTED_LOCATION_DEBUGSIMULATION ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM})
endif()

if(NOT TARGET IntelSGX::SDK_Untrusted)
	add_library(IntelSGX::SDK_Untrusted INTERFACE IMPORTED GLOBAL)
	set_target_properties(IntelSGX::SDK_Untrusted PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${INTEL_SGX_SDK_INCLUDE_DIR})
	set_target_properties(IntelSGX::SDK_Untrusted PROPERTIES INTERFACE_LINK_LIBRARIES #We don't use IMPORTED_LOCATION here since there are multiple lib to link.
		"$<$<CONFIG:DebugSimulation>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM}>$<$<AND:$<CONFIG:Debug>,$<NOT:$<CONFIG:DebugSimulation>>>:${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG}>$<$<CONFIG:Release>:${INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE}>" 
	)
endif()

message(STATUS "Finished Adding Intel SGX Targets.")
message(STATUS "")
