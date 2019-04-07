#pragma once

#include <map>
#include <mutex>

#include "../../structs.h"

namespace Decent
{
	namespace Ra
	{
		class ServerX509;
		class States;
		
		namespace WhiteList
		{
			class DecentServer
			{
			public:
				/** \brief	Default constructor */
				DecentServer();

				/** \brief	Destructor */
				virtual ~DecentServer();

				/**
				 * \brief	Check a certificate from a Decent Server (i.e. a node in decentralized network). The
				 * 			public key is first checked to see if it has been accepted previously. If so,
				 * 			VerifyCertAfterward will be called, and its result will be returned. Otherwise,
				 * 			VerifyCertFirstTime will be called to verify the self remote attestation. If the self
				 * 			remote attestation is valid, the certificate will be accepted and AddToWhiteListMap
				 * 			will be called to add the node to the white list, and true will be returned.
				 * 			Otherwise, false will be returned to indicate that the node cannot be accepted.
				 *
				 * \param [in,out]	decentState	The Decent global state.
				 * \param 		  	cert	   	The certificate.
				 *
				 * \return	True if it the given certificate has been accepted before, or is accepted first time
				 * 			and the node is added to the white list, otherwise, false is returned.
				 */
				virtual bool AddTrustedNode(States& decentState, const ServerX509& cert);

				/**
				 * \brief	Query if a public key held by a Decent Server is existing in the trusted Decent
				 * 			Server list already. In other words, if result is true, the queried public key is
				 * 			checked successfully and added to the trusted Decent Server list previously. This
				 * 			function is thread-safe.
				 *
				 * \param	key	The public key in PEM string held by a Decent Server.
				 *
				 * \return	True if it is trusted, false if not.
				 */
				virtual bool IsNodeTrusted(const std::string& key) const;

				/**
				 * \brief	Gets timestamp that stated in the self remote attestation report of a Decent Server,
				 * 			which has been checked as trusted. This function will check if the public key is
				 * 			existing in the trusted Decent Server list; check IsNodeTrusted function for more
				 * 			detail. This function is thread-safe.
				 *
				 * \param 		  	key	   	The public key in PEM string held by a Decent Server.
				 * \param [in,out]	outTime	The output of the timestamp. Note, if the return value is false, this
				 * field is invalid/unchanged.
				 *
				 * \return	Same as IsNodeTrusted.
				 */
				virtual bool GetAcceptedTimestamp(const std::string& key, report_timestamp_t& outTime) const;

			protected:

				/**
				 * \brief	Verify the certificate as it is being verified first time. Thus, the self remote
				 * 			attestation will be verified, and the hash of the Decent Server will be checked
				 * 			against the loaded white list. Hint: child classes can override this function to add
				 * 			more features.
				 *
				 * \param [in,out]	decentState	The Decent global state.
				 * \param 		  	cert	   	The certificate.
				 * \param 		  	pubKeyPem  	The public key PEM string, which has been extracted from the
				 * 								certificate. (The reason to pass it here with the entire
				 * 								certificate is to avoid extracting the public key again.)
				 * \param [in,out]	serverHash 	Output of the hash of the Decent Server.
				 * \param [in,out]	timestamp  	Output of the the timestamp.
				 *
				 * \return	True if it succeeds, false if it fails.
				 */
				virtual bool VerifyCertFirstTime(States& decentState, const ServerX509& cert, const std::string& pubKeyPem, std::string& serverHash, report_timestamp_t& timestamp);

				/**
				 * \brief	Verify the certificate as it has been verified before with the VerifyCertFirstTime.
				 * 			In this class, this function will directly return true, since there is no related
				 * 			features needed now. Hint: child classes can override this function to add more
				 * 			features.
				 *
				 * \param [in,out]	decentState	The Decent global state.
				 * \param 		  	cert	   	The certificate.
				 *
				 * \return	True if it succeeds, false if it fails.
				 */
				virtual bool VerifyCertAfterward(States& decentState, const ServerX509& cert);

				/**
				 * \brief	Add the node to white list map. Usually this is called after a node has been
				 * 			verified. In this class, only the timestamp is simply assigned to the corresponding
				 * 			item in the map. Hint: child classes can override this function to add more features.
				 *
				 * \param [in,out]	decentState	The Decent global state.
				 * \param 		  	cert	   	The certificate.
				 * \param 		  	pubKeyPem  	The public key PEM string, which has been extracted from the
				 * 								certificate. (The reason to pass it here with the entire
				 * 								certificate is to avoid extracting the public key again.)
				 * \param 		  	serverHash 	Input of the hash of the Decent Server.
				 * \param 		  	timestamp  	Input of the the timestamp.
				 *
				 * \return	True if it succeeds, false if it fails.
				 */
				virtual bool AddToWhiteListMap(States& decentState, const ServerX509& cert, const std::string& pubKeyPem, const std::string& serverHash, const report_timestamp_t& timestamp);

			private:
				std::map<std::string, report_timestamp_t> m_acceptedNodes;
				mutable std::mutex m_acceptedNodesMutex;
			};
		}
	}
}