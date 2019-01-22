#pragma once

#include <cstdint>

#include <vector>
#include <string>

#include <boost/filesystem/path.hpp>

#include "FileSystemDefs.h"

namespace fs = boost::filesystem;

namespace Decent
{
	namespace Tools
	{

		fs::path GetKnownFolderPath(KnownFolderType type);

		class FileHandler
		{
		public:
			enum class Mode
			{
				Read,
				Write,
				Append,
				ReadUpdate,
				WriteUpdate,
				AppendUpdate,
			};

			FileHandler() = delete;

			FileHandler(const fs::path filePath, const Mode mode);

			bool Open();
			bool IsOpen() const;
			const Mode GetMode() const;

			bool ReadBlock(std::vector<uint8_t>& binary, size_t size);
			bool WriteBlock(const std::vector<uint8_t>& binary);
			bool WriteString(const std::string& str);

			int FSeek(size_t pos);
			int FSeek(size_t pos, int origin);
			size_t FTell() const;
			void FFlush();

			size_t GetFileSize();
			fs::path GetFilePath() const;

			~FileHandler();

		private:
			const char* InterpretMode(const Mode mode);
			const wchar_t* InterpretModeW(const Mode mode);

			const fs::path m_filePath;
			const Mode m_mode;
			bool m_isWriteAllowed;
			FILE* m_file;
		};
	}
}
