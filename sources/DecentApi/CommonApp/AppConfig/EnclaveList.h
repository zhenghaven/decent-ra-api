#pragma once

#include <map>
#include <string>

#include "../../Common/Tools/JsonForwardDeclare.h"

namespace Decent
{
	namespace Ra
	{
		namespace WhiteList
		{
			class StaticList;
		}
	}

	namespace AppConfig
	{
		class EnclaveListItem
		{
		public: //static members:
			static constexpr char const sk_labelAddr[] = "Address";
			static constexpr char const sk_labelPort[] = "Port";
			static constexpr char const sk_labelIsLoadWl[] = "LoadedWhiteList";
			static constexpr char const sk_labelHash[] = "Hash";

		public:
			EnclaveListItem(const Tools::JsonValue& json);

			EnclaveListItem(const std::string& addr, const uint16_t port, const bool isLoaddedList, const std::string& hashStr) :
				m_addr(addr),
				m_port(port),
				m_loaddedWhiteList(isLoaddedList),
				m_hashStr(hashStr)
			{}

			EnclaveListItem(std::string&& addr, const uint16_t port, const bool isLoaddedList, std::string&& hashStr) :
				m_addr(std::forward<std::string>(addr)),
				m_port(port),
				m_loaddedWhiteList(isLoaddedList),
				m_hashStr(std::forward<std::string>(hashStr))
			{}

			EnclaveListItem(EnclaveListItem&& rhs) :
				EnclaveListItem(std::forward<std::string>(rhs.m_addr),
					rhs.m_port, rhs.m_loaddedWhiteList, std::forward<std::string>(rhs.m_hashStr))
			{}

			EnclaveListItem(const EnclaveListItem& rhs) :
				EnclaveListItem(rhs.m_addr, rhs.m_port, rhs.m_loaddedWhiteList, rhs.m_hashStr)
			{}

			virtual ~EnclaveListItem();

			const std::string& GetAddr() const { return m_addr; }

			uint16_t GetPort() const { return m_port; }

			bool GetIsLoaddedWhiteList() const { return m_loaddedWhiteList; }

			const std::string& GetHashStr() const { return m_hashStr; }

		private:
			std::string m_addr;
			uint16_t m_port;
			bool m_loaddedWhiteList;
			std::string m_hashStr;
		};

		class EnclaveList
		{
		public: //static members:
			static constexpr char const sk_defaultLabel[] = "Enclaves";

		public:
			EnclaveList() = delete;

			EnclaveList(const Json::Value& json);

			virtual ~EnclaveList();

			const EnclaveListItem* GetItemPtr(const std::string name) const;

			const EnclaveListItem& GetItem(const std::string name) const;

			const Ra::WhiteList::StaticList& GetLoadedWhiteList() const { return *m_loadedWhiteList; }

			std::string GetLoadedWhiteListStr() const;

		protected:
			EnclaveList(std::map<std::string, std::unique_ptr<EnclaveListItem> > configMap);

		private:
			std::map<std::string, std::unique_ptr<EnclaveListItem> > m_configMap;
			std::unique_ptr<const Ra::WhiteList::StaticList> m_loadedWhiteList;
		};
	}
}
