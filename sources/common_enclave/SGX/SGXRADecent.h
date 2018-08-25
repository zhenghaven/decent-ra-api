#pragma once

#include <string>
#include <memory>

class SecureCommLayer;

namespace DecentEnclave
{
	void DropDecentNode(const std::string& nodeID);
	//std::shared_ptr<const SecureCommLayer> ReleaseCommLayer(const std::string& nodeID);
	bool IsAttested(const std::string& nodeID);
}