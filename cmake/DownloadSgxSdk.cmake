cmake_minimum_required(VERSION 3.0)

message(STATUS "")
message(STATUS "Checking Intel SGX SDK...")

if(WIN32)

	set(INTEL_SGX_SDK_BIN_URL "")
	set(INTEL_SGX_SDK_BIN_SHA256 "")

elseif(UNIX AND NOT APPLE)

	find_program(LSB_RELEASE_EXEC lsb_release)
	execute_process(COMMAND ${LSB_RELEASE_EXEC} -is
		OUTPUT_VARIABLE LSB_RELEASE_ID_SHORT
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)

	if(LSB_RELEASE_ID_SHORT STREQUAL "Ubuntu")
		message(STATUS "In Ubuntu OS...")
		
		set(INTEL_SGX_SDK_BIN_URL "https://download.01.org/intel-sgx/linux-2.5/ubuntu18.04-server/sgx_linux_x64_sdk_2.5.100.49891.bin")
		set(INTEL_SGX_SDK_BIN_SHA256 "66b2d450196b939a15a955e0b835361d2b7fc195551b2f462a62885c2edb9f8b")

		set(INTEL_SGX_PSW_BIN_URL "https://download.01.org/intel-sgx/linux-2.5/ubuntu18.04-server/libsgx-enclave-common_2.5.100.49891-bionic1_amd64.deb")
		set(INTEL_SGX_PSW_BIN_SHA256 "94053e177422a62e75d3c730cb4235a835036b52f646f05bd4f845681bb7d8c4")

		set(INTEL_SGX_DRI_BIN_URL "https://download.01.org/intel-sgx/linux-2.5/ubuntu18.04-server/sgx_linux_x64_driver_f7dc97c.bin")
		set(INTEL_SGX_DRI_BIN_SHA256 "e62bf0698b6b5563f3526a097e19d2de73fc9d08adaa700fef6fc062e2bb14d3")
		
		set(INTEL_SGX_INSTALL_DIR "/opt/intel/")
		set(INTEL_SGX_SDK_INSTALL_DIR "${INTEL_SGX_INSTALL_DIR}/sgxsdk/")
		set(INTEL_SGX_PSW_INSTALL_DIR "${INTEL_SGX_INSTALL_DIR}/libsgx-enclave-common/")
		
		execute_process(COMMAND uname -r
		OUTPUT_VARIABLE INTEL_SGX_DRI_INSTALL_DIR
		OUTPUT_STRIP_TRAILING_WHITESPACE
		)
		set(INTEL_SGX_DRI_INSTALL_DIR "/lib/modules/${INTEL_SGX_DRI_INSTALL_DIR}/kernel/drivers/intel/sgx/")
		message(STATUS "Got Path to SGX driver: ${INTEL_SGX_DRI_INSTALL_DIR}")
		
		######
		# Install SDK
		######
		set(READ_INSTALLED_SHA256 "N/A")
		if(EXISTS "${INTEL_SGX_SDK_INSTALL_DIR}/SHA256")
		 file(READ ${INTEL_SGX_SDK_INSTALL_DIR}/SHA256 READ_INSTALLED_SHA256)
		endif()
		
		message(STATUS "SDK Ver installed: ${READ_INSTALLED_SHA256}")
		message(STATUS "The version we need: ${INTEL_SGX_SDK_BIN_SHA256}")
		if(NOT ${READ_INSTALLED_SHA256} STREQUAL ${INTEL_SGX_SDK_BIN_SHA256})
		
			message(STATUS "Couldn't find the SDK we need, try to install one...")
			
			file(DOWNLOAD 
			${INTEL_SGX_SDK_BIN_URL}  
			${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_sdk.bin 
			SHOW_PROGRESS
			)
			
			file(SHA256 ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_sdk.bin DOWNLOADED_SHA256)
			
			if(NOT ${DOWNLOADED_SHA256} STREQUAL ${INTEL_SGX_SDK_BIN_SHA256})
				message(FATAL_ERROR "The checksum of downloaded file is invalid!")
			endif()
			
			if(EXISTS "${INTEL_SGX_SDK_INSTALL_DIR}/uninstall.sh")
				execute_process(
					RESULT_VARIABLE exeProcRetVal
					ERROR_VARIABLE  exeProcRetErr
					COMMAND sudo ./uninstall.sh
					WORKING_DIRECTORY "${INTEL_SGX_SDK_INSTALL_DIR}"
					)
				if(NOT ${exeProcRetVal} STREQUAL "0")
					message(FATAL_ERROR "Failed to uninstall the existing SGX SDK. (Err: ${exeProcRetErr})")
				endif()
			endif()
			
			execute_process(
				RESULT_VARIABLE exeProcRetVal
				ERROR_VARIABLE  exeProcRetErr
				COMMAND chmod +x ./sgx_linux_x64_sdk.bin
				COMMAND sudo ./sgx_linux_x64_sdk.bin --prefix=${INTEL_SGX_INSTALL_DIR}
				WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
				)
			if(NOT ${exeProcRetVal} STREQUAL "0")
				message(FATAL_ERROR "Failed to install the SGX SDK. (Err: ${exeProcRetErr})")
			endif()
			
			file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/SDK/SHA256 "${INTEL_SGX_SDK_BIN_SHA256}")
			
			execute_process(
				RESULT_VARIABLE exeProcRetVal
				ERROR_VARIABLE  exeProcRetErr
				COMMAND sudo mv "./SDK/SHA256" "${INTEL_SGX_SDK_INSTALL_DIR}/SHA256"
				WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
				)
			if(NOT ${exeProcRetVal} STREQUAL "0")
				message(FATAL_ERROR "Failed to install the checksum for SGX SDK. (Err: ${exeProcRetErr})")
			endif()
			
			message(STATUS "Successfully installed Intel SGX SDK!")
			
		endif(NOT ${READ_INSTALLED_SHA256} STREQUAL ${INTEL_SGX_SDK_BIN_SHA256})
			
		if(NOT ${CMAKE_BUILD_TYPE} MATCHES "DebugSimulation")
			
			######
			# Install Driver
			######
			set(READ_INSTALLED_SHA256 "N/A")
			if(EXISTS "${INTEL_SGX_DRI_INSTALL_DIR}/SHA256")
			 file(READ ${INTEL_SGX_DRI_INSTALL_DIR}/SHA256 READ_INSTALLED_SHA256)
			endif()
			
			message(STATUS "Driver Ver installed: ${READ_INSTALLED_SHA256}")
			message(STATUS "The version we need: ${INTEL_SGX_DRI_BIN_SHA256}")
			if(NOT ${READ_INSTALLED_SHA256} STREQUAL ${INTEL_SGX_DRI_BIN_SHA256})
			
				message(STATUS "Couldn't find the driver we need, try to install one...")
				
				file(DOWNLOAD 
				${INTEL_SGX_DRI_BIN_URL}  
				${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_driver.bin 
				SHOW_PROGRESS
				)
				
				file(SHA256 ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_driver.bin DOWNLOADED_SHA256)
				
				if(NOT ${DOWNLOADED_SHA256} STREQUAL ${INTEL_SGX_DRI_BIN_SHA256})
					message(FATAL_ERROR "The checksum of downloaded file is invalid!")
				endif()
				
				if(EXISTS "${INTEL_SGX_DRI_INSTALL_DIR}/isgx.ko")
					if(EXISTS "${INTEL_SGX_INSTALL_DIR}/sgxdriver/uninstall.sh")
						execute_process(
							RESULT_VARIABLE exeProcRetVal
							ERROR_VARIABLE  exeProcRetErr
							COMMAND sudo ./uninstall.sh
							WORKING_DIRECTORY "${INTEL_SGX_INSTALL_DIR}/sgxdriver/"
							)
					else()
						execute_process(
							RESULT_VARIABLE exeProcRetVal
							ERROR_VARIABLE  exeProcRetErr
							COMMAND sudo service aesmd stop
							COMMAND sudo /sbin/modprobe -r isgx
							COMMAND sudo rm -rf ${INTEL_SGX_DRI_INSTALL_DIR}
							COMMAND sudo /sbin/depmod
							COMMAND sudo /bin/sed -i '/^isgx$/d' /etc/modules
							WORKING_DIRECTORY "${INTEL_SGX_DRI_INSTALL_DIR}"
							)
					endif()
					if(NOT ${exeProcRetVal} STREQUAL "0")
						message(FATAL_ERROR "Failed to uninstall the existing SGX driver. (Err: ${exeProcRetErr})")
					endif()
				endif()
				
				execute_process(
					RESULT_VARIABLE exeProcRetVal
					ERROR_VARIABLE  exeProcRetErr
					COMMAND chmod +x ./sgx_linux_x64_driver.bin
					COMMAND sudo ./sgx_linux_x64_driver.bin
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				if(NOT ${exeProcRetVal} STREQUAL "0")
					message(FATAL_ERROR "Failed to install the SGX driver. (Err: ${exeProcRetErr})")
				endif()
				
				file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/Driver/SHA256 "${INTEL_SGX_DRI_BIN_SHA256}")
				
				execute_process(
					RESULT_VARIABLE exeProcRetVal
					ERROR_VARIABLE  exeProcRetErr
					COMMAND sudo mv "./Driver/SHA256" "${INTEL_SGX_DRI_INSTALL_DIR}/SHA256"
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				if(NOT ${exeProcRetVal} STREQUAL "0")
					message(FATAL_ERROR "Failed to install the checksum for SGX driver. (Err: ${exeProcRetErr})")
				endif()
				
				message(STATUS "Successfully installed Intel SGX Driver!")
				
			endif(NOT ${READ_INSTALLED_SHA256} STREQUAL ${INTEL_SGX_DRI_BIN_SHA256})
			
			######
			# Install PSW
			######
			set(READ_INSTALLED_SHA256 "N/A")
			if(EXISTS "${INTEL_SGX_PSW_INSTALL_DIR}/SHA256")
			 file(READ ${INTEL_SGX_PSW_INSTALL_DIR}/SHA256 READ_INSTALLED_SHA256)
			endif()
			
			message(STATUS "PSW Ver installed: ${READ_INSTALLED_SHA256}")
			message(STATUS "The version we need: ${INTEL_SGX_PSW_BIN_SHA256}")
			
			if(NOT ${READ_INSTALLED_SHA256} STREQUAL ${INTEL_SGX_PSW_BIN_SHA256})
			
				message(STATUS "Couldn't find the PSW we need, try to install one...")
				
				file(DOWNLOAD 
				${INTEL_SGX_PSW_BIN_URL}  
				${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_psw.deb 
				SHOW_PROGRESS
				)
				
				file(SHA256 ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_psw.deb DOWNLOADED_SHA256)
				
				if(NOT ${DOWNLOADED_SHA256} STREQUAL ${INTEL_SGX_PSW_BIN_SHA256})
					message(FATAL_ERROR "The checksum of downloaded file is invalid!")
				endif()
				
				if(EXISTS "${INTEL_SGX_PSW_INSTALL_DIR}/uninstall.sh")
					execute_process(
						RESULT_VARIABLE exeProcRetVal
						ERROR_VARIABLE  exeProcRetErr
						COMMAND sudo ./uninstall.sh
						COMMAND sudo apt --assume-yes remove libsgx-enclave-common
						WORKING_DIRECTORY "${INTEL_SGX_PSW_INSTALL_DIR}"
						)
					if(NOT ${exeProcRetVal} STREQUAL "0")
							message(FATAL_ERROR "Failed to uninstall the existing SGX PSW. (Err: ${exeProcRetErr})")
					endif()
				endif()
				
				execute_process(
					RESULT_VARIABLE exeProcRetVal
					ERROR_VARIABLE  exeProcRetErr
					COMMAND chmod +x ./sgx_linux_x64_psw.deb
					COMMAND sudo apt --assume-yes install ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_psw.deb
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				if(NOT ${exeProcRetVal} STREQUAL "0")
					message(FATAL_ERROR "Failed to install the SGX PSW. (Err: ${exeProcRetErr})")
				endif()
				
				file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/PSW/SHA256 "${INTEL_SGX_PSW_BIN_SHA256}")
				
				execute_process(
					RESULT_VARIABLE exeProcRetVal
					ERROR_VARIABLE  exeProcRetErr
					COMMAND sudo mv "./PSW/SHA256" "${INTEL_SGX_PSW_INSTALL_DIR}/SHA256"
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				if(NOT ${exeProcRetVal} STREQUAL "0")
					message(FATAL_ERROR "Failed to install the checksum for SGX PSW. (Err: ${exeProcRetErr})")
				endif()
				
				message(STATUS "Successfully installed Intel SGX PSW!")
				
			endif(NOT ${READ_INSTALLED_SHA256} STREQUAL ${INTEL_SGX_PSW_BIN_SHA256})
			
		endif(NOT ${CMAKE_BUILD_TYPE} MATCHES "DebugSimulation")
		
	endif(LSB_RELEASE_ID_SHORT STREQUAL "Ubuntu")

endif()

message(STATUS "Finished Checking/Downloading/Installing Intel SGX SDK.")
message(STATUS "")
