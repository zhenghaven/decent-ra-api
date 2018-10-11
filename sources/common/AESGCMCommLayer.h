#pragma once

#include "SecureCommLayer.h"

#include <memory>
#include <array>

#include "GeneralKeyTypes.h"

class AESGCMCommLayer : virtual public SecureCommLayer
{
public:
	typedef General128BitKey AesGcm128bKeyType;

public:
	AESGCMCommLayer() = delete;
	//Copy is prohibited. 
	AESGCMCommLayer(const AESGCMCommLayer& other) = delete;

	AESGCMCommLayer(const uint8_t sKey[GENERAL_128BIT_16BYTE_SIZE]);
	AESGCMCommLayer(const AesGcm128bKeyType& sKey);
	AESGCMCommLayer(AesGcm128bKeyType& sKey);
	AESGCMCommLayer(AesGcm128bKeyType&& sKey);
	AESGCMCommLayer(AESGCMCommLayer&& other);

	virtual ~AESGCMCommLayer();

	//Copy is prohibited. 
	AESGCMCommLayer& operator=(const AESGCMCommLayer& other) = delete;

	virtual bool DecryptMsg(std::string& outMsg, const char* inMsg) const override;
	virtual bool DecryptMsg(std::string& outMsg, const std::string& inMsg) const override;

	virtual bool EncryptMsg(std::string& outMsg, const std::string& inMsg) const override;

	virtual bool ReceiveMsg(void* const connectionPtr, std::string& outMsg) const override;
	virtual bool SendMsg(void* const connectionPtr, const std::string& inMsg) const override;

private:
	AesGcm128bKeyType m_sk;
};
