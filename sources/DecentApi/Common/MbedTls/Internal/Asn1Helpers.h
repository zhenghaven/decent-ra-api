#pragma once

#include <string>

#include <mbedtls/asn1.h>
#include <mbedtls/platform.h>

#include "../MbedTlsException.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			inline const mbedtls_asn1_named_data& Asn1FindNamedData(const mbedtls_asn1_named_data& list, const std::string& oid)
			{
				const mbedtls_asn1_named_data* curr = &list;
				while (curr != NULL)
				{
					if (curr->oid.len == oid.size() &&
						memcmp(curr->oid.p, oid.data(), oid.size()) == 0)
					{
						return *curr;
					}

					curr = curr->next;
				}

				throw RuntimeException("The given OID is not found in the list.");
			}

			inline void Asn1DeepCopy(mbedtls_asn1_buf& dest, const mbedtls_asn1_buf& src)
			{
				if (src.p == nullptr)
				{
					dest.p = nullptr;
				}
				else
				{
					dest.p = static_cast<unsigned char *>(mbedtls_calloc(1, src.len));
					if (dest.p == nullptr)
					{
						throw RuntimeException("Bad allocation.");
					}
				}
				
				dest.len = src.len;
				dest.tag = src.tag;
				std::memcpy(dest.p, src.p, src.len);
			}

			//Dest is a pointer holding named data. If there is already something stored in dest (not-null), it will be freed.
			inline void Asn1DeepCopy(mbedtls_asn1_named_data*& dest, const mbedtls_asn1_named_data& src)
			{
				mbedtls_asn1_free_named_data_list(&dest);

				dest = static_cast<mbedtls_asn1_named_data*>(mbedtls_calloc(1, sizeof(mbedtls_asn1_named_data)));
				if (dest == nullptr)
				{
					throw RuntimeException("Bad allocation.");
				}

				const mbedtls_asn1_named_data* curSrc = &src;
				mbedtls_asn1_named_data* curDest = dest;

				while (curSrc != nullptr)
				{
					Asn1DeepCopy(curDest->oid, curSrc->oid);
					Asn1DeepCopy(curDest->val, curSrc->val);
					curDest->next_merged = curSrc->next_merged;

					if (curSrc->next != nullptr)
					{
						curDest->next = static_cast<mbedtls_asn1_named_data*>(mbedtls_calloc(1, sizeof(mbedtls_asn1_named_data)));
						if (curDest->next == nullptr)
						{
							throw RuntimeException("Bad allocation.");
						}
					}

					curSrc = curSrc->next;
					curDest = curDest->next;
				}
			}
		}
	}
}
