#define BUILD_ON   1
#define BUILD_OFF  0

//Switches for enclave hardwares:
#define USE_INTEL_SGX_ENCLAVE             BUILD_ON

//Switches for enclave protocols (those requires enclave hardware):
#define USE_DECENTRALIZED_ENCLAVE         BUILD_ON
#define USE_DECENT_ENCLAVE                BUILD_ON
#define USE_DECENT_ENCLAVE_SERVER         BUILD_ON
#define USE_DECENT_ENCLAVE_APP            BUILD_ON

//Switches for enclave protocols (those do not requires enclave hardware):
//For now it's fine to let them compile.
//#define USE_DECENT_ENCLAVE_CLIENT       BUILD_ON
