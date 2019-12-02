# Decent Enclave Framework

## Requirements
- Check compatibility of computer's hardware. 
  - Some computer doesn't have or support the SGX hardware. If the computer doesn't support, try to use the simulation mode to develop the program.
- Install [CMake](https://cmake.org/download/)
- Install [Intel SGX SDK](https://software.intel.com/en-us/sgx/sdk)
  - For **Windows**, install the following libraries/tools/programs:
    1. go to [Intel SGX SDK](https://software.intel.com/en-us/sgx/sdk) download and install SGX SDK.
    2. Install Perl compiler (For OpenSSL)
    3. Install 7zip (For OpenSSL)
    4. Install NASM (For OpenSSL)
    5. Install Visual Studio (**Note**: currently the Intel SGX debug plug-in only supports VS 2015 & 2017)
  - For **Ubuntu**:
    - The CMake script should download and install the necessary SDK properly. (Note: It may override the existing installation)
    - **Note:** These scripts may install some required library packages using command "sudo apt-get install ...".
    - If the CMake script doesn't work properly, you may find the necessary libraries/tools/programs at [https://software.intel.com/en-us/sgx/sdk](https://software.intel.com/en-us/sgx/sdk)
    - The following libraries/tools/programs is required:
      1. Driver
      2. SDK
      3. PSW (this is required for hardware mode).

## Clone this repo
- When cloning the repo, make sure you recursively __**clone all the submodules**__ (use command "git submodule update --init --recursive").
