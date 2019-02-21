#pragma once

#include <map>
#include <memory>
#include <string>
#include <exception>

namespace Json
{
	class Value;
}

namespace Decent
{
	namespace Ra
	{
		namespace WhiteList
		{
			class StaticTypeList;
		}
	}

	namespace Tools
	{
		class ConfigParseException : public std::runtime_error
		{
		public:
			ConfigParseException() :
				std::runtime_error("Configuration File Parse Error!")
			{}

			virtual ~ConfigParseException() {}
		};

		class ConfigItem
		{
		public:
			static constexpr char const sk_labelAddr[] = "Address";
			static constexpr char const sk_labelPort[] = "Port";
			static constexpr char const sk_labelIsLoadWl[] = "LoadedWhiteList";
			static constexpr char const sk_labelHash[] = "Hash";

			ConfigItem(const Json::Value& json);

			ConfigItem(const std::string& addr, const uint16_t port, const bool isLoaddedList, const std::string& hashStr) :
				m_addr(addr),
				m_port(port),
				m_loaddedWhiteList(isLoaddedList),
				m_hashStr(hashStr)
			{}

			ConfigItem(std::string&& addr, const uint16_t port, const bool isLoaddedList, std::string&& hashStr) :
				m_addr(std::forward<std::string>(addr)),
				m_port(port),
				m_loaddedWhiteList(isLoaddedList),
				m_hashStr(std::forward<std::string>(hashStr))
			{}

			ConfigItem(ConfigItem&& rhs) :
				ConfigItem(std::forward<std::string>(rhs.m_addr),
					rhs.m_port, rhs.m_loaddedWhiteList, std::forward<std::string>(rhs.m_hashStr))
			{}

			ConfigItem(const ConfigItem& rhs) :
				ConfigItem(rhs.m_addr, rhs.m_port, rhs.m_loaddedWhiteList, rhs.m_hashStr)
			{}

			const std::string& GetAddr() const { return m_addr; }
			uint16_t GetPort() const { return m_port; }
			bool GetIsLoaddedWhiteList() const { return m_loaddedWhiteList; }
			const std::string& GetHashStr() const { return m_hashStr; }

		private:
			ConfigItem(std::string&& addr, const uint16_t port, const bool isLoaddedList, const Json::Value& json);

			std::string m_addr;
			uint16_t m_port;
			bool m_loaddedWhiteList;
			std::string m_hashStr;
		};

		class ConfigManager
		{
		public:
			ConfigManager() = delete;
			ConfigManager(const std::string& jsonStr);
			ConfigManager(const Json::Value& json);
			~ConfigManager();

			const ConfigItem* GetItemPtr(const std::string name) const;
			const ConfigItem& GetItem(const std::string name) const;

			const Ra::WhiteList::StaticTypeList& GetLoadedWhiteList() const { return *m_loadedWhiteList; }
			std::string GetLoadedWhiteListStr() const;

		protected:
			ConfigManager(std::map<std::string, std::unique_ptr<ConfigItem> >&& configMap);

		private:
			std::map<std::string, std::unique_ptr<ConfigItem> > m_configMap;
			std::unique_ptr<const Ra::WhiteList::StaticTypeList> m_loadedWhiteList;
		};
	}
}
