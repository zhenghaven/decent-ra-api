#pragma once

#include <utility>
#include <memory>

#include "../../common/AESGCMCommLayer.h"

typedef struct _sgx_dh_session_enclave_identity_t sgx_dh_session_enclave_identity_t;

class SGXLACommLayer : public AESGCMCommLayer
{
public:
	SGXLACommLayer() = delete;
	SGXLACommLayer(void* const connectionPtr, bool isInitiator);
	SGXLACommLayer(const SGXLACommLayer& other) = delete;
	SGXLACommLayer(SGXLACommLayer&& other);

	virtual ~SGXLACommLayer();

	const sgx_dh_session_enclave_identity_t* GetIdentity() const;

private:
	bool m_isHandShaked;
	std::unique_ptr<sgx_dh_session_enclave_identity_t> m_identity;

	SGXLACommLayer(std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > keyAndId);
	SGXLACommLayer(std::unique_ptr<General128BitKey>& key, std::unique_ptr<sgx_dh_session_enclave_identity_t>& id, bool isValid);
	static std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > DoHandShake(void* const connectionPtr, bool isInitiator);
};
