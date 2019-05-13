cmake_minimum_required(VERSION 3.10)

macro(setup_non_enclave_enclave_project PROJECT_NAME)

	###########################################################
	### Enclave
	###########################################################

	add_library(${PROJECT_NAME}_Enclave STATIC ${SOURCES_Common} ${SOURCES_Common_Enc} ${SOURCES_${PROJECT_NAME}_Enc})
	#defines:
	target_compile_definitions(${PROJECT_NAME}_Enclave PRIVATE ${COMMON_ENCLAVE_DEFINES} ENCLAVE_PLATFORM_NON_ENCLAVE)
	#compiler flags:
	target_compile_options(${PROJECT_NAME}_Enclave PRIVATE ${INTEL_SGX_SDK_C_FLAGS} $<$<COMPILE_LANGUAGE:CXX>:${INTEL_SGX_SDK_CXX_FLAGS} ${COMMON_ENCLAVE_CXX_OPTIONS}>)
	#linker flags:
	set_target_properties(${PROJECT_NAME}_Enclave PROPERTIES LINK_FLAGS "${ENCLAVE_LINKER_OPTIONS}")
	set_target_properties(${PROJECT_NAME}_Enclave PROPERTIES FOLDER "${PROJECT_NAME}")

	target_link_libraries(${PROJECT_NAME}_Enclave 
		DecentRa_App_App 
		mbedtls 
	)

endmacro()

macro(setup_non_enclave_app_project PROJECT_NAME)

	###########################################################
	### App
	###########################################################

	add_executable(${PROJECT_NAME}_App ${SOURCES_Common} ${SOURCES_Common_App} ${SOURCES_${PROJECT_NAME}_App})
	#includes:
	target_include_directories(${PROJECT_NAME}_App PRIVATE ${TCLAP_INCLUDE_DIR})
	#defines:
	target_compile_definitions(${PROJECT_NAME}_App PRIVATE ${COMMON_APP_DEFINES} ENCLAVE_PLATFORM_NON_ENCLAVE)
	#linker flags:
	set_target_properties(${PROJECT_NAME}_App PROPERTIES LINK_FLAGS_DEBUG "${APP_DEBUG_LINKER_OPTIONS}")
	set_target_properties(${PROJECT_NAME}_App PROPERTIES LINK_FLAGS_DEBUGSIMULATION "${APP_DEBUG_LINKER_OPTIONS}")
	set_target_properties(${PROJECT_NAME}_App PROPERTIES LINK_FLAGS_RELEASE "${APP_RELEASE_LINKER_OPTIONS}")
	set_target_properties(${PROJECT_NAME}_App PROPERTIES FOLDER "${PROJECT_NAME}")

	target_link_libraries(${PROJECT_NAME}_App 
		${COMMON_STANDARD_LIBRARIES} 
		DecentRa_App_App 
		${PROJECT_NAME}_Enclave 
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
