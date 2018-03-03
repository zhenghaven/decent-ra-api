cmake_minimum_required(VERSION 3.0)

#project(Intel_SGX_SDK)

if(WIN32)
	if((NOT DEFINED ENV{SGXSDKInstallPath}) OR (NOT EXISTS "$ENV{SGXSDKInstallPath}"))
		message(FATAL_ERROR "Intel SGX SDK is not installed properly!")
	else()
		get_filename_component(INTEL_SGX_SDK_PATH "$ENV{SGXSDKInstallPath}" ABSOLUTE)
		
		set(INTEL_SGX_INCLUDE_DIRS "${INTEL_SGX_SDK_PATH}/include" PARENT_SCOPE)
		
		#file(GLOB INTEL_SGX_SDK_SRC ${INTEL_SGX_SDK_PATH}/include/*.h ${INTEL_SGX_SDK_PATH}/include/*.cpp)
		
		#include_directories(${INTEL_SGX_SDK_PATH}/include)
		
		#add_library(Intel_SGX_SDK STATIC ${INTEL_SGX_SDK_SRC})
		if("${CMAKE_SIZEOF_VOID_P}" STREQUAL "4")
			#set(INTEL_SGX_RELEASE_LIB_DIRS "${INTEL_SGX_SDK_PATH}/bin/win32/Release" PARENT_SCOPE)
			#set(INTEL_SGX_DEBUG_LIB_DIRS "${INTEL_SGX_SDK_PATH}/bin/x64/Debug" PARENT_SCOPE)
			file(GLOB INTEL_SGX_RELEASE_TRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_trts.lib 
						${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_tservice.lib 
						${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_tstdc.lib 
						${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_tcxx.lib 
						${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_tcrypto.lib)
			file(GLOB INTEL_SGX_RELEASE_UNTRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_uae_service.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Release/sgx_urts.lib)
			file(GLOB INTEL_SGX_DEBUG_TRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_trts.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_tservice.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_tstdc.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_tcxx.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_tcrypto.lib)
			file(GLOB INTEL_SGX_DEBUG_UNTRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_uae_service.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_urts.lib)
			file(GLOB INTEL_SGX_DEBUGSIM_TRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_trts_sim.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_tservice_sim.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_tstdc.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_tcxx.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_tcrypto.lib)
			file(GLOB INTEL_SGX_DEBUGSIM_UNTRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_uae_service_sim.lib
						${INTEL_SGX_SDK_PATH}/bin/win32/Debug/sgx_urts_sim.lib)
			#target_link_libraries(Intel_SGX_SDK $<$<CONFIG:Debug>:${INTEL_SGX_DEBUG_LIB}> $<$<CONFIG:Release>:${INTEL_SGX_RELEASE_LIB}>)
		else()
			#set(INTEL_SGX_RELEASE_LIB_DIRS "${INTEL_SGX_SDK_PATH}/bin/x64/Release" PARENT_SCOPE)
			#set(INTEL_SGX_DEBUG_LIB_DIRS "${INTEL_SGX_SDK_PATH}/bin/x64/Debug" PARENT_SCOPE)
			file(GLOB INTEL_SGX_RELEASE_TRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/x64/Release/sgx_trts.lib 
						${INTEL_SGX_SDK_PATH}/bin/x64/Release/sgx_tservice.lib 
						${INTEL_SGX_SDK_PATH}/bin/x64/Release/sgx_tstdc.lib 
						${INTEL_SGX_SDK_PATH}/bin/x64/Release/sgx_tcxx.lib 
						${INTEL_SGX_SDK_PATH}/bin/x64/Release/sgx_tcrypto.lib)
			file(GLOB INTEL_SGX_RELEASE_UNTRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/x64/Release/sgx_uae_service.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Release/sgx_urts.lib)
			file(GLOB INTEL_SGX_DEBUG_TRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_trts.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_tservice.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_tstdc.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_tcxx.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_tcrypto.lib)
			file(GLOB INTEL_SGX_DEBUG_UNTRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_uae_service.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_urts.lib)
			file(GLOB INTEL_SGX_DEBUGSIM_TRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_trts_sim.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_tservice_sim.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_tstdc.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_tcxx.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_tcrypto.lib)
			file(GLOB INTEL_SGX_DEBUGSIM_UNTRUST_LIB 
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_uae_service_sim.lib
						${INTEL_SGX_SDK_PATH}/bin/x64/Debug/sgx_urts_sim.lib)
			#target_link_libraries(Intel_SGX_SDK $<$<CONFIG:Debug>:${INTEL_SGX_DEBUG_LIB}> $<$<CONFIG:Release>:${INTEL_SGX_RELEASE_LIB}>)
		endif()
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
	else()
		
	endif()
else()
	message(FATAL_ERROR "OS not supported by Intel SGX!")
endif()