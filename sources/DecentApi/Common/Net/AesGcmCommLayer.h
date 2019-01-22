#pragma once

#include "SecureCommLayer.h"

#include <memory>

#include "../GeneralKeyTypes.h"
#include "../MbedTls/MbedTlsObjects.h"

namespace Decent
{
	namespace Net
	{
		class AesGcmCommLayer : virtual public SecureCommLayer
		{
		public:
			typedef General128BitKey AesGcm128bKeyType;

		public:
			AesGcmCommLayer() = delete;
			//Copy is prohibited. 
			AesGcmCommLayer(const AesGcmCommLayer& other) = delete;

			AesGcmCommLayer(const uint8_t(&sKey)[GENERAL_128BIT_16BYTE_SIZE]);
			AesGcmCommLayer(const AesGcm128bKeyType& sKey);
			AesGcmCommLayer(AesGcmCommLayer&& other);

			virtual ~AesGcmCommLayer();

			//Copy is prohibited. 
			AesGcmCommLayer& operator=(const AesGcmCommLayer& other) = delete;
			AesGcmCommLayer& operator=(AesGcmCommLayer&& other);

			virtual operator bool() const override;

			virtual bool DecryptMsg(std::string& outMsg, const std::string& inMsg);// override;

			virtual bool EncryptMsg(std::string& outMsg, const std::string& inMsg);// override;

			virtual bool ReceiveMsg(void* const connectionPtr, std::string& outMsg) override;
			virtual bool SendMsg(void* const connectionPtr, const std::string& inMsg) override;

		private:
			MbedTlsObj::Aes128Gcm m_gcm;
		};
	}
}
