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
			file(GLOB INTEL_SGX_RELEASE_LIB ${INTEL_SGX_SDK_PATH}/bin/win32/Release/*.lib)
			file(GLOB INTEL_SGX_DEBUG_LIB ${INTEL_SGX_SDK_PATH}/bin/win32/Debug/*.lib)
			#target_link_libraries(Intel_SGX_SDK $<$<CONFIG:Debug>:${INTEL_SGX_DEBUG_LIB}> $<$<CONFIG:Release>:${INTEL_SGX_RELEASE_LIB}>)
		else()
			file(GLOB INTEL_SGX_RELEASE_LIB ${INTEL_SGX_SDK_PATH}/bin/x64/Release/*.lib)
			file(GLOB INTEL_SGX_DEBUG_LIB ${INTEL_SGX_SDK_PATH}/bin/x64/Debug/*.lib)
			#target_link_libraries(Intel_SGX_SDK $<$<CONFIG:Debug>:${INTEL_SGX_DEBUG_LIB}> $<$<CONFIG:Release>:${INTEL_SGX_RELEASE_LIB}>)
		endif()
		set(INTEL_SGX_RELEASE_LIB "${INTEL_SGX_RELEASE_LIB}" PARENT_SCOPE)
		set(INTEL_SGX_DEBUG_LIB "${INTEL_SGX_DEBUG_LIB}" PARENT_SCOPE)
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