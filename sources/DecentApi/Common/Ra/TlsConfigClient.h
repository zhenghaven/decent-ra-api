#pragma once

#include "TlsConfigWithName.h"

namespace Decent
{
	namespace Ra
	{
		class ClientX509;

		class TlsConfigClient : public TlsConfigWithName
		{
		public:
			TlsConfigClient(Decent::Ra::States& state, Mode cntMode, const std::string& expectedVerifierName);

			TlsConfigClient(TlsConfigClient&& other) :
				TlsConfigWithName(std::forward<TlsConfigWithName>(other))
			{}

			TlsConfigClient(const TlsConfigClient& other) = delete;

			virtual ~TlsConfigClient();

			virtual TlsConfigClient& operator=(const TlsConfigClient& other) = delete;

			virtual TlsConfigClient& operator=(TlsConfigClient&& other) = delete;

		protected:
			virtual int VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override;

			virtual int VerifyClientCert(const ClientX509& cert, int depth, uint32_t& flag) const;

		private:
		};
	}
}
