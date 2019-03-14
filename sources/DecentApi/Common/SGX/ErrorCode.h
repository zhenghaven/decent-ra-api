#pragma once

#include <string>

#include <sgx_error.h>

namespace Decent
{
	namespace Sgx
	{
		/**
		 * \brief	Gets error message from the error code
		 *
		 * \exception	Decent::RuntimeException	Unknown error code is given.
		 *
		 * \param	code	The error code.
		 *
		 * \return	Char pointer to the string.
		 */
		const char* GetErrorMessage(const sgx_status_t code);

		/**
		 * \brief	Gets potential solution to the error from the error code
		 *
		 * \exception	Decent::RuntimeException	Unknown error code is given.
		 *
		 * \param	code	The error code.
		 *
		 * \return	Char pointer to the string.
		 */
		const char* GetErrorSolution(const sgx_status_t code);

		std::string ConstructErrorMsg(sgx_status_t errCode, const std::string& funcName);
	}
}
