cmake_minimum_required(VERSION 3.10)

include(${CMAKE_CURRENT_LIST_DIR}/SetupSgxSdkLibs.cmake)

if(MSVC)
	set(BINARY_SUB_DIR "$<CONFIG>")
else()
	set(BINARY_SUB_DIR "")
endif()

macro(setup_sgx_edl_project PROJECT_NAME)

	###########################################################
	### EDL
	###########################################################

	set(EDL_T_SRC_OUTPUT ${SOURCEDIR_${PROJECT_NAME}_Enc}/Enclave_t.h ${SOURCEDIR_${PROJECT_NAME}_Enc}/Enclave_t.c)
	set(EDL_U_SRC_OUTPUT ${SOURCEDIR_${PROJECT_NAME}_App}/Enclave_u.h ${SOURCEDIR_${PROJECT_NAME}_App}/Enclave_u.c)

	add_custom_command(OUTPUT ${EDL_T_SRC_OUTPUT}
		COMMAND "${INTEL_SGX_EDGER_PATH}"
		--trusted "${SOURCEDIR_${PROJECT_NAME}_Enc}/Enclave.edl"
		--search-path "${SOURCEDIR_Common_Enc}"
		--search-path "${SOURCEDIR_${PROJECT_NAME}_Enc}"
		--search-path "${DECENT_API_EDL_DIR}"
		--search-path "${INTEL_SGX_SDK_INCLUDE_DIR}"
		WORKING_DIRECTORY "${SOURCEDIR_${PROJECT_NAME}_Enc}"
		DEPENDS "${SOURCEDIR_${PROJECT_NAME}_Enc}/Enclave.edl"
		COMMENT "Processing EDL for enclave..."
	)

	add_custom_command(OUTPUT ${EDL_U_SRC_OUTPUT}
		COMMAND "${INTEL_SGX_EDGER_PATH}"
		--untrusted "${SOURCEDIR_${PROJECT_NAME}_Enc}/Enclave.edl"
		--search-path "${SOURCEDIR_Common_Enc}"
		--search-path "${SOURCEDIR_${PROJECT_NAME}_Enc}"
		--search-path "${DECENT_API_EDL_DIR}"
		--search-path "${INTEL_SGX_SDK_INCLUDE_DIR}"
		WORKING_DIRECTORY "${SOURCEDIR_${PROJECT_NAME}_App}"
		DEPENDS "${SOURCEDIR_${PROJECT_NAME}_Enc}/Enclave.edl"
		COMMENT "Processing EDL for app..."
	)

	add_custom_target(${PROJECT_NAME}_EDL DEPENDS ${EDL_T_SRC_OUTPUT} ${EDL_U_SRC_OUTPUT})
	set_target_properties(${PROJECT_NAME}_EDL PROPERTIES FOLDER "${PROJECT_NAME}")

endmacro()

macro(setup_sgx_enclave_project PROJECT_NAME)

	###########################################################
	### Enclave
	###########################################################

	add_library(${PROJECT_NAME}_Enclave SHARED ${SOURCES_Common} ${SOURCES_Common_EDL} ${SOURCES_Common_Enc} ${SOURCES_${PROJECT_NAME}_Enc} ${SOURCES_${PROJECT_NAME}_EDL})
	#defines:
	target_compile_definitions(${PROJECT_NAME}_Enclave PRIVATE ${COMMON_ENCLAVE_DEFINES} ENCLAVE_PLATFORM_SGX)
	#compiler flags:
	target_compile_options(${PROJECT_NAME}_Enclave PRIVATE ${INTEL_SGX_SDK_C_FLAGS} $<$<COMPILE_LANGUAGE:CXX>:${INTEL_SGX_SDK_CXX_FLAGS} ${COMMON_ENCLAVE_CXX_OPTIONS}>)
	#linker flags:
	set_target_properties(${PROJECT_NAME}_Enclave PROPERTIES LINK_FLAGS "${ENCLAVE_LINKER_OPTIONS} ${INTEL_SGX_SDK_LINKER_FLAGS_T}")
	set_target_properties(${PROJECT_NAME}_Enclave PROPERTIES FOLDER "${PROJECT_NAME}")

	set(${PROJECT_NAME}_ENCLAVE_SIGNED "${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>.signed${CMAKE_SHARED_LIBRARY_SUFFIX}")
	set(${PROJECT_NAME}_ENCLAVE_LIB "${CMAKE_SHARED_LIBRARY_PREFIX}${PROJECT_NAME}_Enclave$<$<CONFIG:Debug>:${CMAKE_DEBUG_POSTFIX}>${CMAKE_SHARED_LIBRARY_SUFFIX}")

	add_custom_command(TARGET ${PROJECT_NAME}_Enclave
		POST_BUILD
		COMMAND "${INTEL_SGX_SIGNER_PATH}" sign 
		-key "${CMAKE_CURRENT_LIST_DIR}/Enclave_private.pem" 
		-enclave "${CMAKE_BINARY_DIR}/${BINARY_SUB_DIR}/${${PROJECT_NAME}_ENCLAVE_LIB}" 
		-out "${CMAKE_BINARY_DIR}/${${PROJECT_NAME}_ENCLAVE_SIGNED}" 
		-config "${SOURCEDIR_${PROJECT_NAME}_Enc}/Enclave.config.xml"
	)

	target_link_libraries(${PROJECT_NAME}_Enclave 
		${WHOLE_ARCHIVE_FLAG_BEGIN} 
		IntelSGX::Trusted::switchless 
		IntelSGX::Trusted::rts 
		${WHOLE_ARCHIVE_FLAG_END}
		${GROUP_FLAG_BEGIN}
		IntelSGX::Trusted::stdc 
		IntelSGX::Trusted::cxx 
		IntelSGX::Trusted::service 
		IntelSGX::Trusted::key_exchange 
		IntelSGX::Trusted::crypto 
		IntelSGX::Trusted::file_system 
		DecentRa_App_Enclave 
		mbedcrypto_enclave 
		mbedx509_enclave 
		mbedtls_enclave 
		${GROUP_FLAG_END}
	)

	add_dependencies(${PROJECT_NAME}_Enclave ${PROJECT_NAME}_EDL)

endmacro()

macro(setup_sgx_app_project PROJECT_NAME)

	###########################################################
	### App
	###########################################################

	add_executable(${PROJECT_NAME}_App ${SOURCES_Common} ${SOURCES_Common_EDL} ${SOURCES_Common_App} ${SOURCES_${PROJECT_NAME}_App} ${SOURCES_${PROJECT_NAME}_EDL})
	#includes:
	target_include_directories(${PROJECT_NAME}_App PRIVATE ${TCLAP_INCLUDE_DIR})
	#defines:
	target_compile_definitions(${PROJECT_NAME}_App PRIVATE ${COMMON_APP_DEFINES} ENCLAVE_PLATFORM_SGX ENCLAVE_FILENAME="${${PROJECT_NAME}_ENCLAVE_SIGNED}" TOKEN_FILENAME="${PROJECT_NAME}_Enclave.token")
	#linker flags:
	set_target_properties(${PROJECT_NAME}_App PROPERTIES LINK_FLAGS_DEBUG "${APP_DEBUG_LINKER_OPTIONS}")
	set_target_properties(${PROJECT_NAME}_App PROPERTIES LINK_FLAGS_DEBUGSIMULATION "${APP_DEBUG_LINKER_OPTIONS}")
	set_target_properties(${PROJECT_NAME}_App PROPERTIES LINK_FLAGS_RELEASE "${APP_RELEASE_LINKER_OPTIONS}")
	set_target_properties(${PROJECT_NAME}_App PROPERTIES FOLDER "${PROJECT_NAME}")

	target_link_libraries(${PROJECT_NAME}_App 
		${COMMON_STANDARD_LIBRARIES} 
		IntelSGX::Untrusted::Libs
		DecentRa_App_App 
		jsoncpp_lib_static 
		mbedcrypto 
		mbedx509 
		mbedtls 
		Boost::filesystem
		Boost::system
		${Additional_Sys_Lib}
	)

	add_dependencies(${PROJECT_NAME}_App ${PROJECT_NAME}_Enclave)

endmacro()
