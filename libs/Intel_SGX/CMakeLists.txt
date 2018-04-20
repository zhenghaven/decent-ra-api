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
		file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_trts.lib)
		
		file(GLOB INTEL_SGX_SDK_LIB_GROUP_RELEASE 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tservice.lib 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tstdc.lib 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tcxx.lib 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_tcrypto.lib)
		
		file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_uae_service.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Release/sgx_urts.lib)
		
		file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_trts.lib)
		
		file(GLOB INTEL_SGX_SDK_LIB_GROUP_DEBUG 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tservice.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tstdc.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcxx.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcrypto.lib)
		
		file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_uae_service.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_urts.lib)
		
		file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_trts_sim.lib)
		
		file(GLOB INTEL_SGX_SDK_LIB_GROUP_DEBUGSIM 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tservice_sim.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tstdc.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcxx.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_tcrypto.lib)
		
		file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM 
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_uae_service_sim.lib
					${INTEL_SGX_SDK_PATH}/bin/${WIN_ARCHI_STR}/Debug/sgx_urts_sim.lib)
		
		set(INTEL_SGX_CXXLIB_NAME libc++)
elseif(UNIX)
	
	#set(INTEL_SGX_SDK_LIB_PATH "${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}")
	
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_trts.a)
	
	file(GLOB INTEL_SGX_SDK_LIB_GROUP_RELEASE 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tservice.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tstdc.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tcxx.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tcrypto.a)
	
	set(INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE -lsgx_uae_service -lsgx_urts)
	
	
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_trts.a)
	
	file(GLOB INTEL_SGX_SDK_LIB_GROUP_DEBUG 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tservice.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tstdc.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tcxx.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tcrypto.a)
	
	set(INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG -lsgx_uae_service -lsgx_urts)
	
	file(GLOB INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_trts_sim.a)
	
	file(GLOB INTEL_SGX_SDK_LIB_GROUP_DEBUGSIM 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tservice_sim.a
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tstdc.a
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tcxx.a
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_tcrypto.a)
	
	file(GLOB INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM 
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_uae_service_sim.so
				${INTEL_SGX_SDK_PATH}/${LINUX_LIB_ARCHI_STR}/libsgx_urts_sim.so)
	
	# set(INTEL_SGX_RELEASE_TRUST_LIB -Wl,--whole-archive ${INTEL_SGX_RELEASE_TRTS_LIB} -Wl,--no-whole-archive -Wl,--start-group ${INTEL_SGX_RELEASE_TRUST_LIB} -Wl,--end-group PARENT_SCOPE)
	# set(INTEL_SGX_RELEASE_UNTRUST_LIB ${INTEL_SGX_RELEASE_UNTRUST_LIB} PARENT_SCOPE)
	
	# set(INTEL_SGX_DEBUG_TRUST_LIB -Wl,--whole-archive ${INTEL_SGX_RELEASE_TRTS_LIB} -Wl,--no-whole-archive -Wl,--start-group ${INTEL_SGX_DEBUG_TRUST_LIB} -Wl,--end-group PARENT_SCOPE)
	# set(INTEL_SGX_DEBUG_UNTRUST_LIB ${INTEL_SGX_DEBUG_UNTRUST_LIB} PARENT_SCOPE)
	
	# set(INTEL_SGX_DEBUGSIM_TRUST_LIB -Wl,--whole-archive ${INTEL_SGX_DEBUGSIM_TRTS_LIB} -Wl,--no-whole-archive -Wl,--start-group ${INTEL_SGX_DEBUGSIM_TRUST_LIB} -Wl,--end-group PARENT_SCOPE)
	# set(INTEL_SGX_DEBUGSIM_UNTRUST_LIB ${INTEL_SGX_DEBUGSIM_UNTRUST_LIB} PARENT_SCOPE)

	# #Trust Libs
	# set(INTEL_SGX_TRTS_LIB "sgx_trts")
	# set(INTEL_SGX_SIM_TRTS_LIB "${INTEL_SGX_TRTS_LIB}_sim")
	
	# set(INTEL_SGX_TSTDC_LIB "sgx_tstdc")
	# set(INTEL_SGX_SIM_TSTDC_LIB "${INTEL_SGX_TSTDC_LIB}")
	
	# set(INTEL_SGX_TCXX_LIB "sgx_tcxx")
	# set(INTEL_SGX_SIM_TCXX_LIB "${INTEL_SGX_SIM_TCXX_LIB}")
	
	# set(INTEL_SGX_TCRYPTO_LIB "sgx_tcrypto")
	# set(INTEL_SGX_SIM_TCRYPTO_LIB "${INTEL_SGX_TCRYPTO_LIB}")
	
	# set(INTEL_SGX_TSERVICE_LIB "sgx_tservice")
	# set(INTEL_SGX_SIM_TSERVICE_LIB "${INTEL_SGX_TSERVICE_LIB}_sim")
	
	# #Untrust Libs
	# set(INTEL_SGX_URTS_LIB "sgx_urts")
	# set(INTEL_SGX_SIM_URTS_LIB "${INTEL_SGX_TSERVICE_LIB}_sim")
	
	# set(INTEL_SGX_UAESERV_LIB "lsgx_uae_service")
	# set(INTEL_SGX_SIM_UAESERV_LIB "${INTEL_SGX_TSERVICE_LIB}_sim")
	
	#C Flags:
	set(INTEL_SGX_SDK_C_FLAGS -nostdinc -fvisibility=hidden -fpie -fstack-protector)
	#CXX Flags:
	set(INTEL_SGX_SDK_CXX_FLAGS -nostdinc++ -std=c++11)
	
	#Linker Flags (Trusted, Hardware Mode):
	set(INTEL_SGX_SDK_LINKER_FLAGS_T_HW "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0")
	
	#Linker Flags (Trusted, Simulation Mode):
	set(INTEL_SGX_SDK_LINKER_FLAGS_T_SIM "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0")
	
	#Linker Flags (Untrusted, Hardware Mode):
	set(INTEL_SGX_SDK_LINKER_FLAGS_U_HW "-lpthread")
	
	#Linker Flags (Untrusted, Simulation Mode):
	set(INTEL_SGX_SDK_LINKER_FLAGS_U_SIM "-lpthread")
	
	#Change Scope
	# set(INTEL_SGX_C_FLAGS ${INTEL_SGX_C_FLAGS} PARENT_SCOPE)
	# set(INTEL_SGX_CXX_FLAGS ${INTEL_SGX_CXX_FLAGS} PARENT_SCOPE)
	# set(INTEL_SGX_T_LINKER_FLAGS ${INTEL_SGX_T_LINKER_FLAGS} PARENT_SCOPE)
	# set(INTEL_SGX_T_SIM_LINKER_FLAGS ${INTEL_SGX_T_SIM_LINKER_FLAGS} PARENT_SCOPE)
	# set(INTEL_SGX_U_LINKER_FLAGS ${INTEL_SGX_U_LINKER_FLAGS} PARENT_SCOPE)
	# set(INTEL_SGX_U_SIM_LINKER_FLAGS ${INTEL_SGX_U_SIM_LINKER_FLAGS} PARENT_SCOPE)
	
	set(INTEL_SGX_CXXLIB_NAME libcxx)
	
endif()

############################
# SGX SSL
############################
include(sgxssl.cmake)

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
# ${INTEL_SGX_SDK_LINKER_FLAGS_T_HW}
# ${INTEL_SGX_SDK_LINKER_FLAGS_T_SIM}
# ${INTEL_SGX_SDK_LINKER_FLAGS_U_HW}
# ${INTEL_SGX_SDK_LINKER_FLAGS_U_SIM}

# ${INTEL_SGX_SSL_INCLUDE_PATH}

# ${INTEL_SGX_EDGER_PATH}
# ${INTEL_SGX_SIGNER_PATH}
# ${INTEL_SGX_CXXLIB_NAME}

set(INTEL_SGX_SDK_PATH ${INTEL_SGX_SDK_PATH} PARENT_SCOPE)
set(INTEL_SGX_SDK_INCLUDE_PATH "${INTEL_SGX_SDK_PATH}/include" PARENT_SCOPE)

set(INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUG} PARENT_SCOPE)
set(INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM ${INTEL_SGX_SDK_LIB_WHOLE_ARC_DEBUGSIM} PARENT_SCOPE)
set(INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE ${INTEL_SGX_SDK_LIB_WHOLE_ARC_RELEASE} PARENT_SCOPE)

set(INTEL_SGX_SDK_LIB_GROUP_DEBUG ${INTEL_SGX_SDK_LIB_GROUP_DEBUG} PARENT_SCOPE)
set(INTEL_SGX_SDK_LIB_GROUP_DEBUGSIM ${INTEL_SGX_SDK_LIB_GROUP_DEBUGSIM} PARENT_SCOPE)
set(INTEL_SGX_SDK_LIB_GROUP_RELEASE ${INTEL_SGX_SDK_LIB_GROUP_RELEASE} PARENT_SCOPE)

set(INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG ${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUG} PARENT_SCOPE)
set(INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM ${INTEL_SGX_SDK_LIB_UNTRUSTED_DEBUGSIM} PARENT_SCOPE)
set(INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE ${INTEL_SGX_SDK_LIB_UNTRUSTED_RELEASE} PARENT_SCOPE)

set(INTEL_SGX_SDK_C_FLAGS ${INTEL_SGX_SDK_C_FLAGS} PARENT_SCOPE)
set(INTEL_SGX_SDK_CXX_FLAGS ${INTEL_SGX_SDK_CXX_FLAGS} PARENT_SCOPE)
set(INTEL_SGX_SDK_LINKER_FLAGS_T_HW ${INTEL_SGX_SDK_LINKER_FLAGS_T_HW} PARENT_SCOPE)
set(INTEL_SGX_SDK_LINKER_FLAGS_T_SIM ${INTEL_SGX_SDK_LINKER_FLAGS_T_SIM} PARENT_SCOPE)
set(INTEL_SGX_SDK_LINKER_FLAGS_U_HW ${INTEL_SGX_SDK_LINKER_FLAGS_U_HW} PARENT_SCOPE)
set(INTEL_SGX_SDK_LINKER_FLAGS_U_SIM ${INTEL_SGX_SDK_LINKER_FLAGS_U_SIM} PARENT_SCOPE)



set(INTEL_SGX_EDGER_PATH ${INTEL_SGX_EDGER_PATH} PARENT_SCOPE)
set(INTEL_SGX_SIGNER_PATH ${INTEL_SGX_SIGNER_PATH} PARENT_SCOPE)
set(INTEL_SGX_CXXLIB_NAME ${INTEL_SGX_CXXLIB_NAME} PARENT_SCOPE)
