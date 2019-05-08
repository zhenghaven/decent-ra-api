//#if ENCLAVE_PLATFORM_SGX

#include "../../Common/Common.h"
#include "../../Common/Net/ConnectionBase.h"

using namespace Decent::Net;

extern "C" int ocall_decent_net_cnet_send_pack(void* const ptr, const char* msg, size_t size)
{
	if (!ptr || !msg)
	{
		PRINT_W("Nullptr is given to the ocall_decent_net_cnet_send_pack");
		return false;
	}

	try
	{
		static_cast<ConnectionBase*>(ptr)->SendPack(msg, size);
		return true;
	}
	catch (const std::exception& e)
	{
		PRINT_W("ocall_decent_net_cnet_send_pack failed. Error msg: %s", e.what());
		return false;
	}
}

extern "C" int ocall_decent_net_cnet_recv_pack(size_t* recv_size, void* const ptr, char** msg)
{
	if (!recv_size || !ptr || !msg)
	{
		PRINT_W("Nullptr is given to the ocall_decent_net_cnet_recv_pack");
		return false;
	}

	try
	{
		*recv_size = static_cast<ConnectionBase*>(ptr)->ReceivePack(*msg);
		return true;
	}
	catch (const std::exception& e)
	{
		PRINT_W("ocall_decent_net_cnet_recv_pack failed. Error msg: %s", e.what());
		return false;
	}
}

extern "C" int ocall_decent_net_cnet_send_and_recv_pack(void* const ptr, const char* in_msg, size_t in_size, char** out_msg, size_t* out_size)
{
	if (!ptr || !in_msg || !out_msg || !out_size)
	{
		PRINT_W("Nullptr is given to the ocall_decent_net_cnet_send_and_recv_pack");
		return false;
	}

	try
	{
		static_cast<ConnectionBase*>(ptr)->SendPack(in_msg, in_size);
		*out_size = static_cast<ConnectionBase*>(ptr)->ReceivePack(*out_msg);
		return true;
	}
	catch (const std::exception& e)
	{
		PRINT_W("ocall_decent_net_cnet_send_and_recv_pack failed. Error msg: %s", e.what());
		return false;
	}
}

extern "C" int ocall_decent_net_cnet_send_raw(size_t* sent_size, void* const ptr, const char* msg, size_t size)
{
	if (!sent_size || !ptr || !msg)
	{
		PRINT_W("Nullptr is given to the ocall_decent_net_cnet_send_raw");
		return false;
	}

	try
	{
		*sent_size = static_cast<ConnectionBase*>(ptr)->SendRaw(msg, size);
		return true;
	}
	catch (const std::exception& e)
	{
		PRINT_W("ocall_decent_net_cnet_send_raw failed. Error msg: %s", e.what());
		return false;
	}
}

extern "C" int ocall_decent_net_cnet_recv_raw(size_t* recv_size, void* const ptr, char* buf, size_t buf_size)
{
	if (!recv_size || !ptr || !buf)
	{
		PRINT_W("Nullptr is given to the ocall_decent_net_cnet_recv_raw");
		return false;
	}

	try
	{
		*recv_size = static_cast<ConnectionBase*>(ptr)->ReceiveRaw(buf, buf_size);
		return true;
	}
	catch (const std::exception& e)
	{
		PRINT_W("ocall_decent_net_cnet_recv_raw failed. Error msg: %s", e.what());
		return false;
	}
}

extern "C" void ocall_decent_net_cnet_terminate(void* cnt_ptr)
{
	if (!cnt_ptr)
	{
		return;
	}

	try
	{
		static_cast<ConnectionBase*>(cnt_ptr)->Terminate();
	}
	catch (const std::exception& e)
	{}
}

extern "C" void ocall_decent_net_cnet_close(void* cnt_ptr)
{
	delete static_cast<ConnectionBase*>(cnt_ptr);
}

//#endif //ENCLAVE_PLATFORM_SGX