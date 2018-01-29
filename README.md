# KeyManage
Enclave Key Management System

## Requirements
* Check compatibility of computer's hardware.
* Install [Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk/download)
* Install Perl compiler ([ActivePerl](https://www.activestate.com/activeperl/downloads))
* Install [CMake](https://cmake.org/download/)
* For Windows OS, Install Visual Studio (Note: currently the Intel SGX only supports VS 2015)
* For Linux, use gcc, g++, and/or CLion.

## Build
### For Windows
1. Directly Run setup-win.bat
2. Go to "build" directory, open the VS solution file.

### For Linux or Mac
1. Create a "build" directory
2. pushd build
3. cmake ../
4. make
5. popd
