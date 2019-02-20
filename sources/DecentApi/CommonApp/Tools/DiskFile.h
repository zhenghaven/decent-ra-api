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
		class DiskFile :public FileBase
		{
		public:
			DiskFile() = delete;

			DiskFile(const boost::filesystem::path& filePath, const Mode mode, DeferOpen);

			DiskFile(const boost::filesystem::path& filePath, const Mode mode) :
				DiskFile(filePath, mode, sk_deferOpen)
			{
				Open();
			}

			DiskFile(const DiskFile& rhs) = delete;

			DiskFile(DiskFile&& rhs) :
				FileBase(std::forward<DiskFile>(rhs)),
				m_filePath(std::forward<std::unique_ptr<boost::filesystem::path> >(rhs.m_filePath)),
				m_file(rhs.m_file)
			{
				rhs.m_file = nullptr;
			}

			~DiskFile();

			virtual void Open() override;
			virtual bool IsOpen() const override { return m_file != nullptr; }

			virtual int FSeek(const size_t pos) override;
			virtual int FSeek(const size_t pos, const int origin) override;
			virtual size_t FTell() const override;
			virtual void FFlush() override;

			virtual size_t GetFileSize() override;

			virtual operator bool() const { return FileBase::operator bool() && IsOpen(); }

		protected:
			virtual size_t ReadBlockRaw(void* buffer, const size_t size) override;
			virtual size_t WriteBlockRaw(const void* buffer, const size_t size) override;

			std::string GetFilePathStr() const;

		private:
			std::unique_ptr<boost::filesystem::path> m_filePath;
			FILE* m_file;
		};
	}
}
