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
		
		set(INTEL_SGX_SDK_BIN_URL "https://download.01.org/intel-sgx/linux-2.3.1/ubuntu18.04/sgx_linux_x64_sdk_2.3.101.46683.bin")
		set(INTEL_SGX_SDK_BIN_SHA256 "6483fd98dfaabf6f2ad2987b7bba562fabb92fb0da19285c7a298d5080b8de13")

		set(INTEL_SGX_PSW_BIN_URL "https://download.01.org/intel-sgx/linux-2.3.1/ubuntu18.04/libsgx-enclave-common_2.3.101.46683-1_amd64.deb")
		set(INTEL_SGX_PSW_BIN_SHA256 "2b29bb006cd2542e417d92ebf4bb7c7f1effac144698ae6746e98427e99df308")

		set(INTEL_SGX_DRI_BIN_URL "https://download.01.org/intel-sgx/linux-2.3.1/ubuntu18.04/sgx_linux_x64_driver_4d69b9c.bin")
		set(INTEL_SGX_DRI_BIN_SHA256 "3b171fa3a2f0ce0415cdc77431d744213f094725b5bd26d8fb661970c1937c9b")
		
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
					COMMAND sudo ./uninstall.sh
					WORKING_DIRECTORY "${INTEL_SGX_SDK_INSTALL_DIR}"
					)
			endif()
			
			execute_process(
				COMMAND chmod +x ./sgx_linux_x64_sdk.bin
				COMMAND sudo ./sgx_linux_x64_sdk.bin --prefix=${INTEL_SGX_INSTALL_DIR}
				WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
				)
			
			file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/SDK/SHA256 "${INTEL_SGX_SDK_BIN_SHA256}")
			
			execute_process(
				COMMAND sudo mv "./SDK/SHA256" "${INTEL_SGX_SDK_INSTALL_DIR}/SHA256"
				WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
				)
			
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
							COMMAND sudo ./uninstall.sh
							WORKING_DIRECTORY "${INTEL_SGX_INSTALL_DIR}/sgxdriver/"
							)
					else()
						execute_process(
							COMMAND sudo service aesmd stop
							COMMAND sudo /sbin/modprobe -r isgx
							COMMAND sudo rm -rf ${INTEL_SGX_DRI_INSTALL_DIR}
							COMMAND sudo /sbin/depmod
							COMMAND sudo /bin/sed -i '/^isgx$/d' /etc/modules
							WORKING_DIRECTORY "${INTEL_SGX_DRI_INSTALL_DIR}"
							)
					endif()
				endif()
				
				execute_process(
					COMMAND chmod +x ./sgx_linux_x64_driver.bin
					COMMAND sudo ./sgx_linux_x64_driver.bin
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				
				file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/Driver/SHA256 "${INTEL_SGX_DRI_BIN_SHA256}")
				
				execute_process(
					COMMAND sudo mv "./Driver/SHA256" "${INTEL_SGX_DRI_INSTALL_DIR}/SHA256"
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				
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
						COMMAND sudo ./uninstall.sh
						COMMAND sudo apt remove libsgx-enclave-common
						WORKING_DIRECTORY "${INTEL_SGX_PSW_INSTALL_DIR}"
						)
				endif()
				
				execute_process(
					COMMAND chmod +x ./sgx_linux_x64_psw.deb
					COMMAND sudo apt install ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_psw.deb
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				
				file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/PSW/SHA256 "${INTEL_SGX_PSW_BIN_SHA256}")
				
				execute_process(
					COMMAND sudo mv "./PSW/SHA256" "${INTEL_SGX_PSW_INSTALL_DIR}/SHA256"
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				
				message(STATUS "Successfully installed Intel SGX PSW!")
				
			endif(NOT ${READ_INSTALLED_SHA256} STREQUAL ${INTEL_SGX_PSW_BIN_SHA256})
			
		endif(NOT ${CMAKE_BUILD_TYPE} MATCHES "DebugSimulation")
		
	endif(LSB_RELEASE_ID_SHORT STREQUAL "Ubuntu")

endif()

message(STATUS "Finished Checking Intel SGX SDK.")
message(STATUS "")
