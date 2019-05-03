#pragma once

#include <boost/filesystem/path.hpp>

#include "FileSystemDefs.h"

namespace Decent
{
	namespace Tools
	{
		/**
		 * \brief	Get the path to known folders.
		 *
		 * \param	type	The type.
		 *
		 * \return	The known folder path.
		 */
		boost::filesystem::path GetKnownFolderPath(KnownFolderType type);
	}
}
