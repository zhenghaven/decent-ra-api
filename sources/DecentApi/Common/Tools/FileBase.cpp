#include "FileBase.h"

using namespace Decent::Tools;

const bool FileBase::IsWriteAllowed(const Mode mode)
{
	switch (mode)
	{
	case FileBase::Mode::Read:
		return false;
	case FileBase::Mode::Write:
		return true;
	case FileBase::Mode::Append:
		return true;
	case FileBase::Mode::ReadUpdate:
		return false;
	case FileBase::Mode::WriteUpdate:
		return true;
	case FileBase::Mode::AppendUpdate:
		return true;
	default:
		throw FileException("Specified mode is not found!");
	}
}

const char* FileBase::InterpretMode(const Mode mode)
{
	switch (mode)
	{
	case FileBase::Mode::Read:
		return "rb";
	case FileBase::Mode::Write:
		return "wb";
	case FileBase::Mode::Append:
		return "ab";
	case FileBase::Mode::ReadUpdate:
		return "r+b";
	case FileBase::Mode::WriteUpdate:
		return "w+b";
	case FileBase::Mode::AppendUpdate:
		return "a+b";
	default:
		throw FileException("Specified mode is not found!");
	}
}

const wchar_t * FileBase::InterpretModeW(const Mode mode)
{
	switch (mode)
	{
	case FileBase::Mode::Read:
		return L"rb";
	case FileBase::Mode::Write:
		return L"wb";
	case FileBase::Mode::Append:
		return L"ab";
	case FileBase::Mode::ReadUpdate:
		return L"r+b";
	case FileBase::Mode::WriteUpdate:
		return L"w+b";
	case FileBase::Mode::AppendUpdate:
		return L"a+b";
	default:
		throw FileException("Specified mode is not found!");
	}
}

FileBase::~FileBase()
{
}
