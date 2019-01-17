#pragma once

#include <utility>
#include <memory>

#include "../../common/AESGCMCommLayer.h"

typedef struct _sgx_dh_session_enclave_identity_t sgx_dh_session_enclave_identity_t;

namespace Sgx
{
	class LocAttCommLayer : public AESGCMCommLayer
	{
	public:
		LocAttCommLayer() = delete;
		LocAttCommLayer(void* const connectionPtr, bool isInitiator);
		LocAttCommLayer(const LocAttCommLayer& other) = delete;
		LocAttCommLayer(LocAttCommLayer&& other);

		virtual ~LocAttCommLayer();

		virtual operator bool() const override;
		const sgx_dh_session_enclave_identity_t* GetIdentity() const;

	private:
		bool m_isHandShaked;
		std::unique_ptr<sgx_dh_session_enclave_identity_t> m_identity;

		LocAttCommLayer(std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > keyAndId);
		LocAttCommLayer(std::unique_ptr<General128BitKey>& key, std::unique_ptr<sgx_dh_session_enclave_identity_t>& id, bool isValid);
		static std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > DoHandShake(void* const connectionPtr, bool isInitiator);
	};
}

