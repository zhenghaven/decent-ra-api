#pragma once

#include "../../Common/Tools/FileBase.h"

namespace Decent
{
	namespace Tools
	{
		class PlainFile : virtual public FileBase
		{
		public:
			PlainFile() = delete;

			PlainFile(const std::string& path, const Mode mode);

			PlainFile(const std::string& path, const Mode mode, DeferOpen);

			PlainFile(const PlainFile& rhs) = delete;

			PlainFile(PlainFile&& rhs);

			virtual ~PlainFile();

			virtual void Open() override;

			virtual bool IsOpen() const override { return m_file != nullptr; }

			virtual int FSeek(const int64_t pos) override;
			virtual int FSeek(const int64_t pos, const int origin) override;
			virtual size_t FTell() const override;

			virtual operator bool() const { return IsOpen(); }

		protected:
			PlainFile(const std::string& path, const char* modeStr);

			virtual size_t ReadBlockRaw(void* buffer, const size_t size) override;

			void* GetFilePtr() { return m_file; }

			const std::string& GetPath() { return m_path; }

		private:
			std::string m_path;
			const char* m_modeChar;
			void* m_file;
		};

		class WritablePlainFile : public PlainFile, virtual public WritableFileBase
		{
		public:
			WritablePlainFile() = delete;

			WritablePlainFile(const std::string& path, const WritableMode mode);

			WritablePlainFile(const std::string& path, const WritableMode mode, DeferOpen);

			WritablePlainFile(const WritablePlainFile& rhs) = delete;

			WritablePlainFile(WritablePlainFile&& rhs);

			virtual ~WritablePlainFile();

			virtual void Open() override { return PlainFile::Open(); }
			virtual bool IsOpen() const override { return PlainFile::IsOpen(); }

			virtual int FSeek(const int64_t pos) override { return PlainFile::FSeek(pos); }
			virtual int FSeek(const int64_t pos, const int origin) override { return PlainFile::FSeek(pos, origin); }
			virtual size_t FTell() const override { return PlainFile::FTell(); }
			virtual void FFlush() override;

			virtual size_t GetFileSize() override { return PlainFile::GetFileSize(); }

		protected:
			virtual size_t WriteBlockRaw(const void* buffer, const size_t size) override;

			virtual size_t ReadBlockRaw(void* buffer, const size_t size) override { return PlainFile::ReadBlockRaw(buffer, size); }
		};
	}
}
