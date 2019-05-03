#pragma once

#include "EnclaveCntTranslator.h"
#include "../../Common/Net/NetworkException.h"

namespace Decent
{
	namespace Net
	{
		/** \brief	An OCall connector that uses OCall function to establish connections. */
		class EnclaveConnectionOwner : public EnclaveCntTranslator
		{
		public: //static members:
			/**
			* \brief	Build connection by calling function to the application side (e.g. OCall in SGX).
			*
			* \exception	Decent::Net::Exception	Thrown when an exception error condition occurs. Error
			* 										conditions are OCall failed, or the connection pointer
			* 										received is null.
			*
			* \tparam	ExpResT	Type of the expected result.
			* \tparam	FuncT  	Type of the OCall function, which must has the forms of "sgx_status_t
			* 					FuncName(void* connection_ptr, ...)", where the "..." means any number of
			* 					parameters, not the variable argument list.
			* \tparam	Args   	Type of the arguments.
			* \param	expRes	  	The expected result.
			* \param	cntBuilder	The OCall function.
			* \param	args	  	Variable arguments providing [in,out] The arguments.
			*
			* \return	The connection pointer.
			*/
			template<typename ExpResT, class FuncT, class... Args>
			static void* CntBuilder(ExpResT expRes, FuncT cntBuilder, Args&&... args)
			{
				void* res = nullptr;
				if ((*cntBuilder)(&res, std::forward<Args>(args)...) == expRes &&
					res != nullptr)
				{
					return res;
				}
				throw Decent::Net::Exception("Failed to establish connection inside Enclave.");
			}

			/**
			* \brief	Build connection by calling function to the application side (e.g. OCall in SGX).
			*
			* \exception	Decent::Net::Exception	Thrown when an exception error condition occurs. Error
			* 										conditions are OCall failed, or the connection pointer
			* 										received is null.
			*
			* \tparam	FuncT	Type of the OCall function, which must has the forms of "sgx_status_t
			* 					FuncName(void* connection_ptr, ...)", where the "..." means any number of
			* 					parameters, not the variable argument list.
			* \tparam	Args 	Type of the arguments.
			* \param	cntBuilder	The OCall function.
			* \param	args	  	Variable arguments providing [in,out] The arguments.
			*
			* \return	The connection pointer.
			*/
			template<class FuncT, class... Args>
			static void* CntBuilderVoid(FuncT cntBuilder, Args&&... args)
			{
				void* res = nullptr;
				(*cntBuilder)(&res, std::forward<Args>(args)...);
				if (res != nullptr)
				{
					return res;
				}
				throw Decent::Net::Exception("Failed to establish connection inside Enclave.");
			}

		public:
			using EnclaveCntTranslator::EnclaveCntTranslator;

			/** \brief	Destructor */
			virtual ~EnclaveConnectionOwner();
		};
	}
}
