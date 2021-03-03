#pragma once

#include "../../Common/Tools/FileBase.h"

#include <mbedTLScpp/SKey.hpp>

namespace Decent
{
	namespace Tools
	{
		class SecureFile : virtual public FileBase
		{
		public:
			SecureFile() = delete;

			SecureFile(const std::string& path, const Mode mode);

			SecureFile(const std::string& path, const Mode mode, DeferOpen);

			SecureFile(const std::string& path, const mbedTLScpp::SKey<128>& key, const Mode mode);

			SecureFile(const std::string& path, const mbedTLScpp::SKey<128>& key, const Mode mode, DeferOpen);

			SecureFile(const SecureFile& rhs) = delete;

			SecureFile(SecureFile&& rhs);

			virtual ~SecureFile();

			virtual void Open() override;

			virtual bool IsOpen() const override { return m_file != nullptr; }

			virtual int FSeek(const int64_t pos) override;
			virtual int FSeek(const int64_t pos, const int origin) override;
			virtual size_t FTell() const override;

			virtual operator bool() const { return IsOpen(); }

		protected:
			SecureFile(const std::string& path, std::unique_ptr<mbedTLScpp::SKey<128> > key, const char* modeStr);

			virtual size_t ReadBlockRaw(void* buffer, const size_t size) override;

			void* GetFilePtr() { return m_file; }

			const std::string& GetPath() { return m_path; }

		private:
			std::string m_path;
			std::unique_ptr<mbedTLScpp::SKey<128> > m_userKey;
			const char* m_modeChar;
			void* m_file;
		};

		class WritableSecureFile : public SecureFile, virtual public WritableFileBase
		{
		public:
			WritableSecureFile() = delete;

			WritableSecureFile(const std::string& path, const WritableMode mode);

			WritableSecureFile(const std::string& path, const WritableMode mode, DeferOpen);

			WritableSecureFile(const std::string& path, const mbedTLScpp::SKey<128>& key, const WritableMode mode);

			WritableSecureFile(const std::string& path, const mbedTLScpp::SKey<128>& key, const WritableMode mode, DeferOpen);

			WritableSecureFile(const WritableSecureFile& rhs) = delete;

			WritableSecureFile(WritableSecureFile&& rhs);

			virtual ~WritableSecureFile();

			virtual void Open() override { return SecureFile::Open(); }
			virtual bool IsOpen() const override { return SecureFile::IsOpen(); }

			virtual int FSeek(const int64_t pos) override { return SecureFile::FSeek(pos); }
			virtual int FSeek(const int64_t pos, const int origin) override { return SecureFile::FSeek(pos, origin); }
			virtual size_t FTell() const override { return SecureFile::FTell(); }
			virtual void FFlush() override;

			virtual size_t GetFileSize() override { return SecureFile::GetFileSize(); }

		protected:
			virtual size_t WriteBlockRaw(const void* buffer, const size_t size) override;

			virtual size_t ReadBlockRaw(void* buffer, const size_t size) override { return SecureFile::ReadBlockRaw(buffer, size); }
		};
	}
}
