#pragma once
// -*- C++ -*-
//===-------------------------- memory ------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is dual licensed under the MIT and the University of Illinois Open
// Source Licenses. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Notes for Decent:
// SGX SDK does not support C++14 standard, thus, we need to include make_unique manually.
// The definition of make_unique is from LLVM.
// To avoid the conflict of definition in std namespace when compiling non-enclave code, 
// we encapsulated these in our own namespace.

#include <memory>

namespace Decent
{
	namespace Tools
	{
		template<class _Tp>
		struct __unique_if
		{
			typedef std::unique_ptr<_Tp> __unique_single;
		};

		template<class _Tp>
		struct __unique_if<_Tp[]>
		{
			typedef std::unique_ptr<_Tp[]> __unique_array_unknown_bound;
		};

		template<class _Tp, size_t _Np>
		struct __unique_if<_Tp[_Np]>
		{
			typedef void __unique_array_known_bound;
		};

		template<class _Tp, class... _Args>
		inline typename __unique_if<_Tp>::__unique_single
			make_unique(_Args&&... __args)
		{
			return std::unique_ptr<_Tp>(new _Tp(std::forward<_Args>(__args)...));
		}

		template<class _Tp>
		inline typename __unique_if<_Tp>::__unique_array_unknown_bound
			make_unique(size_t __n)
		{
			typedef typename std::remove_extent<_Tp>::type _Up;
			return std::unique_ptr<_Tp>(new _Up[__n]());
		}

		template<class _Tp, class... _Args>
		typename __unique_if<_Tp>::__unique_array_known_bound
			make_unique(_Args&&...) = delete;
	}
}
