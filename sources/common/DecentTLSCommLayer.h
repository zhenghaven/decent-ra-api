#pragma once

#include "TLSCommLayer.h"

class DecentTLSCommLayer : public TLSCommLayer
{
public:
	DecentTLSCommLayer() = delete;
	DecentTLSCommLayer(const DecentTLSCommLayer& other) = delete;

	virtual ~DecentTLSCommLayer();

};
