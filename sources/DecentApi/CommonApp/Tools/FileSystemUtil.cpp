#include "FileSystemUtil.h"

#ifdef _WIN32
#include <ShlObj.h>
#include <wchar.h>
#else

#endif // _WIN32

#include <boost/filesystem.hpp>

using namespace Decent::Tools;
namespace fs = boost::filesystem;

fs::path Decent::Tools::GetKnownFolderPath(KnownFolderType type)
{
	switch (type)
	{
	case KnownFolderType::WorkingDir:
		return fs::path(".");
	case KnownFolderType::Temp:
	{
		const char* tempPath = std::getenv("TEMP");
		const char* tmpPath = std::getenv("TMP");
		if (tempPath)
		{
			return fs::path(tempPath);
		}
		else if (tmpPath)
		{
			return fs::path(tmpPath);
		}
		else
		{
			return fs::path("./~tmp/");
		}
	}
	}
#ifdef _WIN32
	
	KNOWNFOLDERID folderId;
	switch (type)
	{
	case KnownFolderType::LocalAppData:
	case KnownFolderType::LocalAppDataEnclave:
		folderId = FOLDERID_LocalAppData;
		break;
	case KnownFolderType::Home:
		folderId = FOLDERID_Profile;
		break;
	case KnownFolderType::Desktop:
		folderId = FOLDERID_Desktop;
		break;
	case KnownFolderType::Documents:
		folderId = FOLDERID_Documents;
		break;
	case KnownFolderType::Downloads:
		folderId = FOLDERID_Downloads;
		break;
	case KnownFolderType::Music:
		folderId = FOLDERID_Music;
		break;
	case KnownFolderType::Pictures:
		folderId = FOLDERID_Pictures;
		break;
	case KnownFolderType::Videos:
		folderId = FOLDERID_Videos;
		break;
	}
	LPWSTR winPath = NULL;
	HRESULT result = SHGetKnownFolderPath(folderId, 0, NULL, &winPath);
	if (result == S_OK)
	{
		fs::path resPath(winPath);
		CoTaskMemFree(winPath);

		if (type == KnownFolderType::LocalAppDataEnclave)
		{
			resPath.append("EnclaveApps");
		}
		return resPath;
	}
	
#else
	const char* homePath = std::getenv("HOME");
	if (homePath)
	{
		fs::path resPath(homePath);
		switch (type)
		{
		case KnownFolderType::Home:
		case KnownFolderType::LocalAppData:
			break;
		case KnownFolderType::LocalAppDataEnclave:
			resPath.append("EnclaveApps");
			break;
		case KnownFolderType::Desktop:
			resPath.append("Desktop");
			break;
		case KnownFolderType::Documents:
			resPath.append("Documents");
			break;
		case KnownFolderType::Downloads:
			resPath.append("Downloads");
			break;
		case KnownFolderType::Music:
			resPath.append("Music");
			break;
		case KnownFolderType::Pictures:
			resPath.append("Pictures");
			break;
		case KnownFolderType::Videos:
			resPath.append("Videos");
			break;
		}
		return resPath;
	}
#endif // _WIN32
	return fs::path(".");
}
