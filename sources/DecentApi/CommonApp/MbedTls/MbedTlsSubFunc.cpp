#include "../../Common/MbedTls/MbedTlsSubFunc.h"

#include <mutex>
#include <memory>

#include "../../Common/Common.h"

using namespace Decent;

struct MyMutexStruct
{
	std::mutex m_mutex;
	std::unique_ptr<std::unique_lock<std::mutex> > m_lock;

	MyMutexStruct() noexcept :
		m_mutex(), //noexcept
		m_lock() //noexcept
	{
	}
};

void MbedTls::mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex)
	{
		//PRINT_I("Nullptr received in mbedtls_mutex_init.");
		return;
	}

	*mutex = new MyMutexStruct();
}

void MbedTls::mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex)
	{
		//PRINT_I("Nullptr received in mbedtls_mutex_free.");
		return;
	}

	MyMutexStruct* myMutex = static_cast<MyMutexStruct*>(*mutex);
	delete myMutex;
	*mutex = nullptr;
}

int MbedTls::mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex || !(*mutex))
	{
		//PRINT_I("Nullptr received in mbedtls_mutex_lock.");
		return -1;
	}

	MyMutexStruct* myMutex = static_cast<MyMutexStruct*>(*mutex);

	try
	{
		std::unique_ptr<std::unique_lock<std::mutex> > lockPtr = std::make_unique<std::unique_lock<std::mutex> >(myMutex->m_mutex);
		myMutex->m_lock = std::move(lockPtr);
	}
	catch (const std::exception&)
	{
		PRINT_I("MbedTLS Failed to lock the mutex.");
		return -1;
	}

	return 0;
}

int MbedTls::mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex || !(*mutex))
	{
		//PRINT_I("Nullptr received in mbedtls_mutex_unlock.");
		return -1;
	}

	MyMutexStruct* myMutex = static_cast<MyMutexStruct*>(*mutex);

	try
	{
		myMutex->m_lock.reset();
	}
	catch (const std::exception&)
	{
		PRINT_I("MbedTLS Failed to unlock the mutex.");
		return -1;
	}

	return 0;
}
