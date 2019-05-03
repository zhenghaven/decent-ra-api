#pragma once

#include "../../Common/Tools/FileBase.h"

#include <memory>

namespace boost
{
	namespace filesystem
	{
		class path;
	}
}

namespace Decent
{
	namespace Tools
	{
		class DiskFile : virtual public FileBase
		{
		public: //static members:
#ifdef _WIN32
			typedef wchar_t* CharType;
			typedef const wchar_t* ConstCharType;
			static ConstCharType GenericInterpretMode(const Mode mode) { return FileBase::InterpretModeW(mode); }

			static void* FopenExclusive(const wchar_t* filePath, const wchar_t* mode);
#else
			typedef char* CharType;
			typedef const char* ConstCharType;
			static ConstCharType GenericInterpretMode(const Mode mode) { return FileBase::InterpretMode(mode); }
#endif

			static void* FopenExclusive(const char* filePath, const char* mode);

		public:
			DiskFile() = delete;

			DiskFile(const boost::filesystem::path& filePath, const Mode mode, bool isExclusive, DeferOpen);

			DiskFile(const boost::filesystem::path& filePath, const Mode mode, bool isExclusive);

			DiskFile(const DiskFile& rhs) = delete;

			DiskFile(DiskFile&& rhs);

			virtual ~DiskFile();

			virtual void Open() override;
			virtual bool IsOpen() const override { return m_file != nullptr; }

			virtual int FSeek(const int64_t pos) override;
			virtual int FSeek(const int64_t pos, const int origin) override;
			virtual size_t FTell() const override;

			virtual operator bool() const { return IsOpen(); }

		protected:
			DiskFile(const boost::filesystem::path& filePath, ConstCharType modeStr, bool isExclusive);

			virtual size_t ReadBlockRaw(void* buffer, const size_t size) override;

			std::string GetFilePathStr() const;

			FILE* GetFilePtr() { return m_file; }

		private:
			std::unique_ptr<boost::filesystem::path> m_filePath;
			FILE* m_file;
			ConstCharType m_fileModeStr;
			bool m_isExclusive;
		};

		class WritableDiskFile : public DiskFile, virtual public WritableFileBase
		{
		public: //static members:
#ifdef _WIN32
			static ConstCharType GenericInterpretMode(const WritableMode mode) { return WritableDiskFile::InterpretModeW(mode); }
#else
			static ConstCharType GenericInterpretMode(const WritableMode mode) { return WritableDiskFile::InterpretMode(mode); }
#endif

		public:
			WritableDiskFile(const boost::filesystem::path& filePath, const WritableMode mode, bool isExclusive, DeferOpen);

			WritableDiskFile(const boost::filesystem::path& filePath, const WritableMode mode, bool isExclusive);

			WritableDiskFile(const WritableDiskFile& rhs) = delete;

			WritableDiskFile(WritableDiskFile&& rhs);

			virtual ~WritableDiskFile();

			virtual void Open() override { return DiskFile::Open(); }
			virtual bool IsOpen() const override { return DiskFile::IsOpen(); }

			virtual int FSeek(const int64_t pos) override { return DiskFile::FSeek(pos); }
			virtual int FSeek(const int64_t pos, const int origin) override { return DiskFile::FSeek(pos, origin); }
			virtual size_t FTell() const override { return DiskFile::FTell(); }
			virtual void FFlush() override;

			virtual size_t GetFileSize() override { return DiskFile::GetFileSize(); }

		protected:
			virtual size_t WriteBlockRaw(const void* buffer, const size_t size) override;

			virtual size_t ReadBlockRaw(void* buffer, const size_t size) override { return DiskFile::ReadBlockRaw(buffer, size); }
		};
	}
}
