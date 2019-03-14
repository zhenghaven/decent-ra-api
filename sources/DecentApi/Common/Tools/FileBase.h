#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include "../RuntimeException.h"

namespace Decent
{
	namespace Tools
	{
		class FileException : public Decent::RuntimeException
		{
		public:
			using RuntimeException::RuntimeException;

		};

		class FileBase
		{
		public: //Static Members:
			struct DeferOpen {};
			static constexpr DeferOpen sk_deferOpen{};

			enum class Mode
			{
				Read,
				ReadUpdate,
			};

		public:
			virtual ~FileBase() {}

			virtual void Open() = 0;
			virtual bool IsOpen() const = 0;

			virtual int FSeek(const size_t pos) = 0;
			virtual int FSeek(const size_t pos, const int origin) = 0;
			virtual size_t FTell() const = 0;

			virtual size_t GetFileSize() = 0;

			virtual void ReadBlockExactSize(std::vector<uint8_t>& buffer)
			{
				if (ReadBlock(buffer) != buffer.size())
				{
					throw FileException("Failed to read all data as required!");
				}
			}

			virtual void ReadBlockExactSize(std::string& buffer)
			{
				if (ReadBlock(buffer) != buffer.size())
				{
					throw FileException("Failed to read all data as required!");
				}
			}

			virtual size_t ReadBlock(std::vector<uint8_t>& buffer)
			{
				return ReadBlockRaw(buffer.data(), buffer.size());
			}

			virtual size_t ReadBlock(std::string& buffer)
			{
				return ReadBlockRaw(&buffer[0], buffer.size());
			}

		protected:
			static const char* InterpretMode(const Mode mode);
			static const wchar_t* InterpretModeW(const Mode mode);

			virtual size_t ReadBlockRaw(void* buffer, const size_t size) = 0;
		};

		class WritableFileBase : virtual public FileBase
		{
		public: //Static Members:
			enum class WritableMode
			{
				Write,
				Append,
				WriteUpdate,
				AppendUpdate,
			};

		public:

			virtual void FFlush() = 0;

			virtual void WriteBlockExactSize(const std::vector<uint8_t>& buffer)
			{
				if (WriteBlock(buffer) != buffer.size())
				{
					throw FileException("Failed to write all data as required!");
				}
			}

			virtual void WriteBlockExactSize(const std::string& buffer)
			{
				if (WriteBlock(buffer) != buffer.size())
				{
					throw FileException("Failed to write all data as required!");
				}
			}

			virtual size_t WriteBlock(const std::vector<uint8_t>& buffer)
			{
				return WriteBlockRaw(buffer.data(), buffer.size());
			}

			virtual size_t WriteBlock(const std::string& buffer)
			{
				return WriteBlockRaw(buffer.data(), buffer.size());
			}

		protected:
			static const char* InterpretMode(const WritableMode mode);
			static const wchar_t* InterpretModeW(const WritableMode mode);

			virtual size_t WriteBlockRaw(const void* buffer, const size_t size) = 0;
		};
	}
}
