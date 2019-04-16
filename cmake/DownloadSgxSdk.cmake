cmake_minimum_required(VERSION 3.0)

message(STATUS "")
message(STATUS "Checking Intel SGX SDK...")

FUNCTION(Download_Package_And_Check SourceUrl DestPath ExpectedHash)
	file(DOWNLOAD
		${SourceUrl}
		${DestPath}
		#SHOW_PROGRESS
	)
	
	file(SHA256 ${DestPath} DOWNLOADED_SHA256)
	
	if(NOT ${DOWNLOADED_SHA256} STREQUAL ${ExpectedHash})
		message(FATAL_ERROR "The checksum of downloaded file, ${DestPath}, is unexpected!")
	endif()
ENDFUNCTION()

FUNCTION(Install_Checksum_Linux TmpFilePath CheckSum InstallationDirPath)
	file(WRITE ${TmpFilePath} "${CheckSum}")
	
	execute_process(
		RESULT_VARIABLE exeProcRetVal
		ERROR_VARIABLE  exeProcRetErr
		COMMAND sudo mv "${TmpFilePath}" "./SHA256"
		WORKING_DIRECTORY "${InstallationDirPath}"
		)
	if(NOT ${exeProcRetVal} STREQUAL "0")
		message(FATAL_ERROR "Failed to install the checksum in ${InstallationDirPath}. (Err: ${exeProcRetErr})")
	endif()
ENDFUNCTION()

FUNCTION(Uninsall_Checksum_Linux ParentPath)
	if(EXISTS "${ParentPath}/SHA256")
		execute_process(
			RESULT_VARIABLE exeProcRetVal
			ERROR_VARIABLE  exeProcRetErr
			COMMAND sudo rm -f "${ParentPath}/SHA256"
			WORKING_DIRECTORY "${ParentPath}"
			)
		if(NOT ${exeProcRetVal} STREQUAL "0")
				message(FATAL_ERROR "Failed to uninstall the checksum for ${ParentPath}. (Err: ${exeProcRetErr})")
		endif()
	endif()
ENDFUNCTION()

FUNCTION(Cleanup_Installation_Linux DirPath ScriptPath)
	if(EXISTS "${DirPath}/${ScriptPath}")
		execute_process(
			RESULT_VARIABLE exeProcRetVal
			ERROR_VARIABLE  exeProcRetErr
			COMMAND sudo "./${ScriptPath}"
			WORKING_DIRECTORY "${DirPath}"
			)
		if(NOT ${exeProcRetVal} STREQUAL "0")
				message(FATAL_ERROR "Failed to cleanup the directory, ${DirPath}. (Err: ${exeProcRetErr})")
		endif()
	endif()
ENDFUNCTION()

FUNCTION(Uninstall_SGX_PSW_Linux)
	if(EXISTS "${INTEL_SGX_PSW_INSTALL_DIR}")
		execute_process(
			RESULT_VARIABLE exeProcRetVal
			ERROR_VARIABLE  exeProcRetErr
			COMMAND sudo apt --assume-yes remove libsgx-enclave-common
			WORKING_DIRECTORY "${INTEL_SGX_PSW_INSTALL_DIR}"
			)
		if(NOT ${exeProcRetVal} STREQUAL "0")
				message(FATAL_ERROR "Failed to uninstall the existing SGX PSW. (Err: ${exeProcRetErr})")
		endif()
		
		Cleanup_Installation_Linux(${INTEL_SGX_PSW_INSTALL_DIR} "cleanup.sh")
		Cleanup_Installation_Linux(${INTEL_SGX_PSW_INSTALL_DIR} "uninstall.sh")
		
		Uninsall_Checksum_Linux(${INTEL_SGX_PSW_INSTALL_DIR})
	endif()
ENDFUNCTION()

FUNCTION(Uninstall_SGX_Driver_Manual_Linux)
	if(EXISTS "${INTEL_SGX_DRI_INSTALL_DIR}/isgx.ko")
		
		Uninstall_SGX_PSW_Linux()
		
		execute_process(
			RESULT_VARIABLE exeProcRetVal
			ERROR_VARIABLE  exeProcRetErr
			#COMMAND sudo service aesmd stop
			COMMAND sudo /sbin/modprobe -r isgx
			COMMAND sudo rm -rf ${INTEL_SGX_DRI_INSTALL_DIR}
			COMMAND sudo /sbin/depmod
			COMMAND sudo /bin/sed -i '/^isgx$/d' /etc/modules
			WORKING_DIRECTORY "${INTEL_SGX_DRI_INSTALL_DIR}"
			)
		if(NOT ${exeProcRetVal} STREQUAL "0")
			message(FATAL_ERROR "Failed to uninstall the existing SGX driver. (Err: ${exeProcRetErr})")
		endif()
	endif()
ENDFUNCTION()

FUNCTION(Uninstall_SGX_Driver_Script_Linux)
	
	Uninstall_SGX_PSW_Linux()
	
	Cleanup_Installation_Linux("${INTEL_SGX_INSTALL_DIR}/sgxdriver" "uninstall.sh")
	
ENDFUNCTION()

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
		
		set(INTEL_SGX_SDK_BIN_URL "https://download.01.org/intel-sgx/linux-2.3/ubuntu18.04-desktop/sgx_linux_x64_sdk_2.3.100.46354.bin")
		set(INTEL_SGX_SDK_BIN_SHA256 "21f71dc8d70d6b3a33983edfdea727ca637c14bf3910f56d8a4d608915213834")

		set(INTEL_SGX_PSW_BIN_URL "https://download.01.org/intel-sgx/linux-2.3/ubuntu18.04-desktop/libsgx-enclave-common_2.3.100.46354-1_amd64.deb")
		set(INTEL_SGX_PSW_BIN_SHA256 "6b03936a2e0d547a0739db5190f717e2f6c1c181466a430fd1a0a53e925ae9bb")

		set(INTEL_SGX_DRI_BIN_URL "https://download.01.org/intel-sgx/linux-2.3/ubuntu18.04-desktop/sgx_linux_x64_driver_4d69b9c.bin")
		set(INTEL_SGX_DRI_BIN_SHA256 "9562acc72a91ebc9572fd8c72b3b332af8b9d98c2b5ad4beced58ebeb5228ed6")
		
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
			
			set(INTEL_SGX_SDK_BIN_DOWNLOADED_PATH ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_sdk.bin)
			
			Download_Package_And_Check(${INTEL_SGX_SDK_BIN_URL} ${INTEL_SGX_SDK_BIN_DOWNLOADED_PATH} ${INTEL_SGX_SDK_BIN_SHA256})
			
			Cleanup_Installation_Linux(${INTEL_SGX_SDK_INSTALL_DIR} "uninstall.sh")
			
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
			
			set(INTEL_SGX_SDK_BIN_HASH_TMP_PATH ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/SDK/SHA256)
			
			Install_Checksum_Linux(${INTEL_SGX_SDK_BIN_HASH_TMP_PATH} ${INTEL_SGX_SDK_BIN_SHA256} ${INTEL_SGX_SDK_INSTALL_DIR})
			
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
				
				set(INTEL_SGX_DRI_BIN_DOWNLOADED_PATH ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_driver.bin)
				
				Download_Package_And_Check(${INTEL_SGX_DRI_BIN_URL} ${INTEL_SGX_DRI_BIN_DOWNLOADED_PATH} ${INTEL_SGX_DRI_BIN_SHA256})
				
				## The uninstallation script came from the package is buggy.
				#Uninstall_SGX_Driver_Script_Linux()
				
				Uninstall_SGX_Driver_Manual_Linux()
				
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
				
				set(INTEL_SGX_DRI_BIN_HASH_TMP_PATH ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/SDK/SHA256)
				
				Install_Checksum_Linux(${INTEL_SGX_DRI_BIN_HASH_TMP_PATH} ${INTEL_SGX_DRI_BIN_SHA256} ${INTEL_SGX_DRI_INSTALL_DIR})
				
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
				
				set(INTEL_SGX_PSW_BIN_DOWNLOADED_PATH ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/sgx_linux_x64_psw.deb)
				
				Download_Package_And_Check(${INTEL_SGX_PSW_BIN_URL} ${INTEL_SGX_PSW_BIN_DOWNLOADED_PATH} ${INTEL_SGX_PSW_BIN_SHA256})
				
				Uninstall_SGX_PSW_Linux()
				
				execute_process(
					RESULT_VARIABLE exeProcRetVal
					ERROR_VARIABLE  exeProcRetErr
					COMMAND chmod +x ./sgx_linux_x64_psw.deb
					COMMAND sudo apt --assume-yes install ${INTEL_SGX_PSW_BIN_DOWNLOADED_PATH}
					WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin"
					)
				if(NOT ${exeProcRetVal} STREQUAL "0")
					message(FATAL_ERROR "Failed to install the SGX PSW. (Err: ${exeProcRetErr})")
				endif()
				
				set(INTEL_SGX_PSW_BIN_HASH_TMP_PATH ${CMAKE_CURRENT_BINARY_DIR}/Intel_SGX_Bin/SDK/SHA256)
				
				Install_Checksum_Linux(${INTEL_SGX_PSW_BIN_HASH_TMP_PATH} ${INTEL_SGX_PSW_BIN_SHA256} ${INTEL_SGX_PSW_INSTALL_DIR})
				
				message(STATUS "Successfully installed Intel SGX PSW!")
				
			endif(NOT ${READ_INSTALLED_SHA256} STREQUAL ${INTEL_SGX_PSW_BIN_SHA256})
			
		endif(NOT ${CMAKE_BUILD_TYPE} MATCHES "DebugSimulation")
		
	endif(LSB_RELEASE_ID_SHORT STREQUAL "Ubuntu")

endif()

message(STATUS "Finished Checking/Downloading/Installing Intel SGX SDK.")
message(STATUS "")
