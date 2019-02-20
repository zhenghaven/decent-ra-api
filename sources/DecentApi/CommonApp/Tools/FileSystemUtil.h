#pragma once

#include <boost/filesystem/path.hpp>

#include "FileSystemDefs.h"

namespace Decent
{
	namespace Tools
	{

		boost::filesystem::path GetKnownFolderPath(KnownFolderType type);

	}
}
