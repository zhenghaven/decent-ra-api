#include "../../Common/Tools/FileSystemUtil.h"

#include <sgx_tprotected_fs.h>

using namespace Decent;

int Tools::FileSysDeleteFile(const std::string& path)
{
	return sgx_remove(path.c_str());
}
