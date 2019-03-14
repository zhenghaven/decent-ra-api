#pragma once

#include <string>

namespace Decent
{
	namespace Tools
	{
		/**
		 * \brief	Deletes the file from file system. Check remove() in stdio.h for details.
		 *
		 * \param	path	Full pathname of the file.
		 *
		 * \return	0 if the file is deleted successfully. Non-zero if failed.
		 */
		int FileSysDeleteFile(const std::string& path);

	}
}
