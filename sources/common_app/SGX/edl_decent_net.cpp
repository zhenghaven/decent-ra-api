//#if ENCLAVE_PLATFORM_SGX

#include "../Net/Connection.h"

using namespace Decent::Net;

extern "C" int ocall_decent_net_cnet_send_pack(void* const ptr, const char* msg, size_t size)
{
	if (!ptr || !msg)
	{
		return false;
	}

	try
	{
		reinterpret_cast<Connection*>(ptr)->SendPack(msg, size);
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

extern "C" size_t ocall_decent_net_cnet_recv_pack(void* const ptr, char** msg)
{
	if (!ptr || !msg)
	{
		return 0;
	}

	try
	{
		return reinterpret_cast<Connection*>(ptr)->ReceivePack(*msg);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

extern "C" int ocall_decent_net_cnet_send_and_recv_pack(void* const ptr, const char* in_msg, size_t in_size, char** out_msg, size_t* out_size)
{
	if (!ptr || !in_msg || !out_msg || !out_size)
	{
		return false;
	}

	try
	{
		reinterpret_cast<Connection*>(ptr)->SendPack(in_msg, in_size);
		*out_size = reinterpret_cast<Connection*>(ptr)->ReceivePack(*out_msg);
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

extern "C" size_t ocall_decent_net_cnet_send_raw(void* const ptr, const char* msg, size_t size)
{
	if (!ptr || !msg)
	{
		return 0;
	}

	try
	{
		return reinterpret_cast<Connection*>(ptr)->SendRaw(msg, size);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

extern "C" size_t ocall_decent_net_cnet_recv_raw(void* const ptr, char* buf, size_t buf_size)
{
	if (!ptr || !buf)
	{
		return 0;
	}

	try
	{
		return reinterpret_cast<Connection*>(ptr)->ReceiveRaw(buf, buf_size);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

//#endif //ENCLAVE_PLATFORM_SGX