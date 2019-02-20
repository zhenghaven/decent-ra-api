#pragma once

#include <cstdint>

#include <string>
#include <vector>
#include <exception>

namespace Decent
{
	namespace Tools
	{
		class FileException : public std::runtime_error
		{
		public:
			FileException(const std::string& message) :
				std::runtime_error(message)
			{}

			virtual ~FileException() {}
		};

		class FileBase
		{
		public:
			struct DeferOpen {};
			static constexpr DeferOpen sk_deferOpen{};

			enum class Mode
			{
				Read,
				Write,
				Append,
				ReadUpdate,
				WriteUpdate,
				AppendUpdate,
			};

			FileBase() = delete;

			FileBase(const Mode mode) :
				m_mode(mode),
				m_isWriteAllowed(IsWriteAllowed(mode)),
				m_isValid(true)
			{}

			FileBase(const FileBase& rhs) = delete;

			FileBase(FileBase&& rhs) :
				m_mode(rhs.m_mode),
				m_isWriteAllowed(rhs.m_isWriteAllowed),
				m_isValid(rhs.m_isValid)
			{
				rhs.m_isValid = false;
			}

			~FileBase();

			virtual void Open() = 0;
			virtual bool IsOpen() const = 0;

			virtual int FSeek(const size_t pos) = 0;
			virtual int FSeek(const size_t pos, const int origin) = 0;
			virtual size_t FTell() const = 0;
			virtual void FFlush() = 0;

			virtual size_t GetFileSize() = 0;

			virtual void ReadBlockExactSize(std::vector<uint8_t>& buffer)
			{
				if (ReadBlock(buffer) != buffer.size())
				{
					throw FileException("Could not read all data as required!");
				}
			}

			virtual void ReadBlockExactSize(std::string& buffer)
			{
				if (ReadBlock(buffer) != buffer.size())
				{
					throw FileException("Could not read all data as required!");
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

			virtual void WriteBlockExactSize(const std::vector<uint8_t>& buffer)
			{
				if (WriteBlock(buffer) != buffer.size())
				{
					throw FileException("Could not write all data as required!");
				}
			}

			virtual void WriteBlockExactSize(const std::string& buffer)
			{
				if (WriteBlock(buffer) != buffer.size())
				{
					throw FileException("Could not write all data as required!");
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

			const Mode GetMode() const { return m_mode; }
			bool IsWriteAllowed() const { return m_isWriteAllowed; }

			virtual operator bool() const { return m_isValid; }

		protected:
			static const char* InterpretMode(const Mode mode);
			static const wchar_t* InterpretModeW(const Mode mode);

			virtual size_t ReadBlockRaw(void* buffer, const size_t size) = 0;
			virtual size_t WriteBlockRaw(const void* buffer, const size_t size) = 0;

		private:
			static const bool IsWriteAllowed(const Mode mode);

			Mode m_mode;
			bool m_isWriteAllowed;
			bool m_isValid;
		};
	}
}
