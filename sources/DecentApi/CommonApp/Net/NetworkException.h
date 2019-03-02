#pragma once

#include "../../Common/Net/NetworkException.h"

#ifdef DEBUG
#include <boost/exception/diagnostic_information.hpp>
#endif // DEBUG

#ifdef DEBUG
#define RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION_BOOST \
		catch (const boost::exception& e) \
		{ \
			std::string errMsg = "Boost Exception:\n"; \
			errMsg += boost::diagnostic_information(e); \
			throw Decent::Net::Exception(errMsg); \
		}
#else
#define RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION_BOOST
#endif // DEBUG

#define RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION(UNKNOWN_EXP_MSG) \
		RETHROW_BOOST_EXCEPTION_AS_DECENT_EXCEPTION_BOOST \
		catch (const std::exception& e) \
		{ \
			throw Decent::Net::Exception(e.what()); \
		} \
		catch (...) \
		{ \
			throw Decent::Net::Exception(UNKNOWN_EXP_MSG); \
		}

