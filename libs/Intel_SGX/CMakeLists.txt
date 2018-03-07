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
		
		set(INTEL_SGX_CXXLIB_NAME libc++ PARENT_SCOPE)
	endif()
elseif(UNIX)
	
	get_filename_component(INTEL_SGX_SDK_PATH "$ENV{SGX_SDK}" ABSOLUTE)
	
	set(INTEL_SGX_INCLUDE_DIRS "${INTEL_SGX_SDK_PATH}/include" PARENT_SCOPE)
	
	if(APPLE)
		message(WARNING "MacOS may need different configuration on Intel SGX")
	endif()
	
	if((NOT DEFINED ENV{SGX_SDK}))
		set(INTEL_SGX_SDK_PATH "/opt/intel/sgxsdk")
	endif()
	
	if((NOT EXISTS ${INTEL_SGX_SDK_PATH}))
		message(FATAL_ERROR "Intel SGX SDK is not installed properly!")
	endif()
	
	set(INTEL_SGX_LIB_PATH "${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}")
	
	#Original way to grab libs.
	file(GLOB INTEL_SGX_RELEASE_TRUST_LIB 
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_tservice.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_tstdc.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_tcxx.a 
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_tcrypto.a)
	file(GLOB INTEL_SGX_RELEASE_TRTS_LIB 
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_trts.a)
	set(INTEL_SGX_RELEASE_UNTRUST_LIB -lsgx_uae_service -lsgx_urts)
	set(INTEL_SGX_DEBUG_TRUST_LIB ${INTEL_SGX_RELEASE_TRUST_LIB})
	set(INTEL_SGX_DEBUG_UNTRUST_LIB ${INTEL_SGX_RELEASE_UNTRUST_LIB})
	file(GLOB INTEL_SGX_DEBUGSIM_TRUST_LIB 
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_tservice_sim.a
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_tstdc_sim.a
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_tcxx_sim.a
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_tcrypto_sim.a)
	file(GLOB INTEL_SGX_DEBUGSIM_TRTS_LIB 
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_trts_sim.a)
	file(GLOB INTEL_SGX_DEBUGSIM_UNTRUST_LIB 
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_uae_service_sim.so
				${INTEL_SGX_SDK_PATH}/${LINUX_ARCHI_STR}/libsgx_urts_sim.so)
	
	set(INTEL_SGX_RELEASE_TRUST_LIB -Wl,--whole-archive ${INTEL_SGX_RELEASE_TRTS_LIB} -Wl,--no-whole-archive -Wl,--start-group ${INTEL_SGX_RELEASE_TRUST_LIB} -Wl,--end-group PARENT_SCOPE)
	set(INTEL_SGX_RELEASE_UNTRUST_LIB ${INTEL_SGX_RELEASE_UNTRUST_LIB} PARENT_SCOPE)
	set(INTEL_SGX_DEBUG_TRUST_LIB -Wl,--whole-archive ${INTEL_SGX_RELEASE_TRTS_LIB} -Wl,--no-whole-archive -Wl,--start-group ${INTEL_SGX_DEBUG_TRUST_LIB} -Wl,--end-group PARENT_SCOPE)
	set(INTEL_SGX_DEBUG_UNTRUST_LIB ${INTEL_SGX_DEBUG_UNTRUST_LIB} PARENT_SCOPE)
	set(INTEL_SGX_DEBUGSIM_TRUST_LIB -Wl,--whole-archive ${INTEL_SGX_DEBUGSIM_TRTS_LIB} -Wl,--no-whole-archive -Wl,--start-group ${INTEL_SGX_DEBUGSIM_TRUST_LIB} -Wl,--end-group PARENT_SCOPE)
	set(INTEL_SGX_DEBUGSIM_UNTRUST_LIB ${INTEL_SGX_DEBUGSIM_UNTRUST_LIB} PARENT_SCOPE)

	#Trust Libs
	set(INTEL_SGX_TRTS_LIB "sgx_trts")
	set(INTEL_SGX_SIM_TRTS_LIB "${INTEL_SGX_TRTS_LIB}_sim")
	
	set(INTEL_SGX_TSTDC_LIB "sgx_tstdc")
	set(INTEL_SGX_SIM_TSTDC_LIB "${INTEL_SGX_TSTDC_LIB}")
	
	set(INTEL_SGX_TCXX_LIB "sgx_tcxx")
	set(INTEL_SGX_SIM_TCXX_LIB "${INTEL_SGX_SIM_TCXX_LIB}")
	
	set(INTEL_SGX_TCRYPTO_LIB "sgx_tcrypto")
	set(INTEL_SGX_SIM_TCRYPTO_LIB "${INTEL_SGX_TCRYPTO_LIB}")
	
	set(INTEL_SGX_TSERVICE_LIB "sgx_tservice")
	set(INTEL_SGX_SIM_TSERVICE_LIB "${INTEL_SGX_TSERVICE_LIB}_sim")
	
	#Untrust Libs
	set(INTEL_SGX_URTS_LIB "sgx_urts")
	set(INTEL_SGX_SIM_URTS_LIB "${INTEL_SGX_TSERVICE_LIB}_sim")
	
	set(INTEL_SGX_UAESERV_LIB "lsgx_uae_service")
	set(INTEL_SGX_SIM_UAESERV_LIB "${INTEL_SGX_TSERVICE_LIB}_sim")
	
	#C Flags:
	set(INTEL_SGX_C_FLAGS -nostdinc -fvisibility=hidden -fpie -fstack-protector)
	#CXX Flags:
	set(INTEL_SGX_CXX_FLAGS -nostdinc++ -std=c++11)
	#Linker Flags (Trusted, Hardware Mode):
	set(INTEL_SGX_T_LINKER_FLAGS "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0")
#-L${INTEL_SGX_LIB_PATH} \
#	-Wl,--whole-archive -l${INTEL_SGX_TRTS_LIB} -Wl,--no-whole-archive \
#	-Wl,--start-group -l${INTEL_SGX_TSTDC_LIB} -l${INTEL_SGX_TCXX_LIB} -l${INTEL_SGX_TCRYPTO_LIB} -l${INTEL_SGX_TSERVICE_LIB} -Wl,--end-group \
	#Linker Flags (Trusted, Simulation Mode):
	set(INTEL_SGX_T_SIM_LINKER_FLAGS "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0")
#-L${INTEL_SGX_LIB_PATH} \
#	-Wl,--whole-archive -l${INTEL_SGX_SIM_TRTS_LIB} -Wl,--no-whole-archive \
#	-Wl,--start-group -l${INTEL_SGX_SIM_TSTDC_LIB} -l${INTEL_SGX_SIM_TCXX_LIB} -l${INTEL_SGX_SIM_TCRYPTO_LIB} -l${INTEL_SGX_SIM_TSERVICE_LIB} -Wl,--end-group \
	#Linker Flags (Untrusted, Hardware Mode):
	set(INTEL_SGX_U_LINKER_FLAGS "-lpthread")
	#Linker Flags (Untrusted, Simulation Mode):
	set(INTEL_SGX_U_SIM_LINKER_FLAGS "-lpthread") #-L${INTEL_SGX_LIB_PATH} -l${INTEL_SGX_SIM_URTS_LIB} -l${INTEL_SGX_SIM_UAESERV_LIB}
	
	#Change Scope
	set(INTEL_SGX_C_FLAGS ${INTEL_SGX_C_FLAGS} PARENT_SCOPE)
	set(INTEL_SGX_CXX_FLAGS ${INTEL_SGX_CXX_FLAGS} PARENT_SCOPE)
	set(INTEL_SGX_T_LINKER_FLAGS ${INTEL_SGX_T_LINKER_FLAGS} PARENT_SCOPE)
	set(INTEL_SGX_T_SIM_LINKER_FLAGS ${INTEL_SGX_T_SIM_LINKER_FLAGS} PARENT_SCOPE)
	set(INTEL_SGX_U_LINKER_FLAGS ${INTEL_SGX_U_LINKER_FLAGS} PARENT_SCOPE)
	set(INTEL_SGX_U_SIM_LINKER_FLAGS ${INTEL_SGX_U_SIM_LINKER_FLAGS} PARENT_SCOPE)
	
	set(INTEL_SGX_CXXLIB_NAME libcxx PARENT_SCOPE)
	
else()
	message(FATAL_ERROR "OS not supported by Intel SGX!")
endif()
