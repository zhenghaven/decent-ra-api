#pragma once

#ifdef ENCLAVE_ENVIRONMENT
namespace rapidjson
{
	class CrtAllocator;

	template <typename BaseAllocator>
	class MemoryPoolAllocator;

	template <typename Encoding, typename Allocator>
	class GenericValue;

	template<typename CharType>
	struct UTF8;

	template <typename Encoding, typename Allocator, typename StackAllocator>
	class GenericDocument;

	typedef GenericValue<UTF8<char>, MemoryPoolAllocator<CrtAllocator> > Value;
	typedef GenericDocument<UTF8<char>, MemoryPoolAllocator<CrtAllocator>, CrtAllocator> Document;
}
#else
namespace Json
{
	class Value;
}
#endif // ENCLAVE_ENVIRONMENT

namespace Decent
{
	namespace Tools
	{

#ifdef ENCLAVE_ENVIRONMENT
		typedef rapidjson::Value JsonValue;
		typedef rapidjson::Document JsonDoc;
#else
		typedef Json::Value JsonValue;
		typedef Json::Value JsonDoc;
#endif // ENCLAVE_ENVIRONMENT

	}
}
