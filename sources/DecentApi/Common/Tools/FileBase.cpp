#include "FileBase.h"

using namespace Decent::Tools;

const char* FileBase::InterpretMode(const Mode mode)
{
	switch (mode)
	{
	case FileBase::Mode::Read:
		return "rb";
	default:
		throw FileException("Specified mode is invalid!");
	}
}

const wchar_t * FileBase::InterpretModeW(const Mode mode)
{
	switch (mode)
	{
	case FileBase::Mode::Read:
		return L"rb";
	default:
		throw FileException("Specified mode is invalid!");
	}
}

const char * Decent::Tools::WritableFileBase::InterpretMode(const WritableMode mode)
{
	switch (mode)
	{
	case WritableMode::Write:
		return "wb";
	case WritableMode::Append:
		return "ab";
	case WritableMode::ReadUpdate:
		return "r+b";
	case WritableMode::WriteUpdate:
		return "w+b";
	case WritableMode::AppendUpdate:
		return "a+b";
	default:
		throw FileException("Specified mode is invalid!");
	}
}

const wchar_t * Decent::Tools::WritableFileBase::InterpretModeW(const WritableMode mode)
{
	switch (mode)
	{
	case WritableMode::Write:
		return L"wb";
	case WritableMode::Append:
		return L"ab";
	case WritableMode::ReadUpdate:
		return L"r+b";
	case WritableMode::WriteUpdate:
		return L"w+b";
	case WritableMode::AppendUpdate:
		return L"a+b";
	default:
		throw FileException("Specified mode is invalid!");
	}
}
