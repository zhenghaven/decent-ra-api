# Decent


## Requirements
- Check compatibility of computer's hardware. 
  - Some computer doesn't have or support the SGX hardware. If the computer doesn't support, try to use the simulation mode to develop the program.
- Install [Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk/download)
  - For **Windows**, install the following programs:
    1. go to [Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk/download) download an install SGX SDK.
    2. Install Perl compiler (recommand: [ActivePerl](https://www.activestate.com/activeperl/downloads)) (For SGX OpenSSL)
    3. Install 7zip (For SGX OpenSSL)
    4. Install NASM (For SGX OpenSSL)
    5. Install Visual Studio (**Note**: currently the Intel SGX debug functions only supports VS 2015)
  - For **Ubuntu**, run the bash script in the order of: 
    1. Driver
    2. SDK
    3. PSW (this is required for hardware mode).
    - **Note:** These scripts may install some required library packages using command "sudo apt-get install ...".
- Install [CMake](https://cmake.org/download/)

## Build
### For Windows
1. Directly Run setup-win.bat
2. Go to "build" directory, open the VS solution file. (In VS, there are three modes available - Hardware debug, Hardware release, and Simulation debug)

### For Linux or Mac
1. Run setup-linux.sh
2. Go to "build" directory, and run "make".
**Note:** setup-linux.sh will generate the project in Hardware Debug mode in default. Use arguments to manually specify build mode (check script file for details).
Or \
The CLion can load the CMakeLists.txt directly.
