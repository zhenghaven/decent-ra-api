cmake_minimum_required(VERSION 3.0)

#project(Intel_SGX_SDK)

if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
	set(WIN_ARCHI_STR "win32")
	set(LINUX_ARCHI_STR "lib")
else()
	set(WIN_ARCHI_STR "x64")
	set(LINUX_ARCHI_STR "lib64")
endif()

if(WIN32)
	if((NOT DEFINED ENV{SGXSDKInstallPath}) OR (NOT EXISTS "$ENV{SGXSDKInstallPath}"))
		message(FATAL_ERROR "Intel SGX SDK is not installed properly!")
	else()
		get_filename_component(INTEL_SGX_SDK_PATH "$ENV{SGXSDKInstallPath}" ABSOLUTE)
		
		set(INTEL_SGX_INCLUDE_DIRS "${INTEL_SGX_SDK_PATH}/include" PARENT_SCOPE)
		
		file(GLOB INTEL_SGX_RELEASE_TRUST_LIB 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_trts.lib 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tservice.lib 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tstdc.lib 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tcxx.lib 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tcrypto.lib)
		file(GLOB INTEL_SGX_RELEASE_UNTRUST_LIB 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_uae_service.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_urts.lib)
		file(GLOB INTEL_SGX_DEBUG_TRUST_LIB 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_trts.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tservice.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tstdc.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcxx.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcrypto.lib)
		file(GLOB INTEL_SGX_DEBUG_UNTRUST_LIB 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_uae_service.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_urts.lib)
		file(GLOB INTEL_SGX_DEBUGSIM_TRUST_LIB 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_trts_sim.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tservice_sim.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tstdc.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcxx.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcrypto.lib)
		file(GLOB INTEL_SGX_DEBUGSIM_UNTRUST_LIB 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_uae_service_sim.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_urts_sim.lib)
		
		set(INTEL_SGX_RELEASE_TRUST_LIB "${INTEL_SGX_RELEASE_TRUST_LIB}" PARENT_SCOPE)
		set(INTEL_SGX_RELEASE_UNTRUST_LIB "${INTEL_SGX_RELEASE_UNTRUST_LIB}" PARENT_SCOPE)
		set(INTEL_SGX_DEBUG_TRUST_LIB "${INTEL_SGX_DEBUG_TRUST_LIB}" PARENT_SCOPE)
		set(INTEL_SGX_DEBUG_UNTRUST_LIB "${INTEL_SGX_DEBUG_UNTRUST_LIB}" PARENT_SCOPE)
		set(INTEL_SGX_DEBUGSIM_TRUST_LIB "${INTEL_SGX_DEBUGSIM_TRUST_LIB}" PARENT_SCOPE)
		set(INTEL_SGX_DEBUGSIM_UNTRUST_LIB "${INTEL_SGX_DEBUGSIM_UNTRUST_LIB}" PARENT_SCOPE)
	endif()
elseif(UNIX)
	if(APPLE)
		message(WARNING "MacOS may need different configuration on Intel SGX")
	endif()
	
	if((NOT DEFINED ENV{SGX_SDK}))
		set(INTEL_SGX_SDK_PATH "/opt/intel/sgxsdk")
	endif()
	
	if((NOT EXISTS ${INTEL_SGX_SDK_PATH}))
		message(FATAL_ERROR "Intel SGX SDK is not installed properly!")
	endif()
	
	
else()
	message(FATAL_ERROR "OS not supported by Intel SGX!")
endif()