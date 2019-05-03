//#if ENCLAVE_PLATFORM_SGX

#include <cstdint>
#include <cstdio>

#include "../Tools/DiskFile.h"

using namespace Decent::Tools;

extern "C" void*  ocall_decent_tools_fopen(const char* filename, const char* mode, int is_exclusive)
{
	try
	{
		if (is_exclusive)
		{
			return DiskFile::FopenExclusive(filename, mode);

		}
		else
		{
			return std::fopen(filename, mode);
		}
	}
	catch (const std::exception&)
	{
		return nullptr;
	}
}

extern "C" int    ocall_decent_tools_fclose(void* file)
{
	return std::fclose(static_cast<FILE*>(file));
}

extern "C" int    ocall_decent_tools_fflush(void* file)
{
	return std::fflush(static_cast<FILE*>(file));
}

extern "C" int    ocall_decent_tools_fseek(void* file, int64_t offset, int origin)
{
	return std::fseek(static_cast<FILE*>(file), static_cast<long>(offset), origin);
}

extern "C" size_t ocall_decent_tools_ftell(void* file)
{
	return static_cast<size_t>(std::ftell(static_cast<FILE*>(file)));
}

extern "C" size_t ocall_decent_tools_fread(void* buffer, size_t buffer_size, void* file)
{
	return std::fread(buffer, sizeof(uint8_t), buffer_size, static_cast<FILE*>(file));
}

extern "C" size_t ocall_decent_tools_fwrite(const void* buffer, size_t buffer_size, void* file)
{
	return std::fwrite(buffer, sizeof(uint8_t), buffer_size, static_cast<FILE*>(file));
}

//#endif //ENCLAVE_PLATFORM_SGX