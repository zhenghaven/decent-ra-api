#pragma once

#include <map>
#include <mutex>

namespace Decent
{
	namespace Ra
	{
		namespace WhiteList
		{
			/**
			 * \brief	Manager for loading application's white lists, which will be embedded in Decent App's
			 * 			certificate later.
			 */
			class AppWhiteListsManager
			{
			public:
				/** \brief	Default constructor */
				AppWhiteListsManager();

				/** \brief	Destructor */
				virtual ~AppWhiteListsManager();

				/**
				 * \brief	Get the white list with the given key (i.e. index). Note: If a application is asking
				 * 			a white list that doesn't exist, we simply see that as that application doesn't have
				 * 			a white list, thus, an empty string will be returned. This function is thread-safe.
				 *
				 * \param	key	The key (i.e. index).
				 *
				 * \return	The white list. If the white list doesn't exist, an empty string will be returned.
				 */
				std::string GetWhiteList(const std::string& key) const;

				/**
				 * \brief	Add a white list
				 *
				 * \param	key			The key (i.e. index).
				 * \param	listJson	The string of white list, which is usually encoded in JSON, however, this
				 * 						function won't check the format of the white list, thus, this more features
				 * 						might be added in future. This function is thread-safe.
				 *
				 * \return	True if it is successfully added, false if it fails. For now, it only return true, as
				 * 			it does not check the format of the white list.
				 */
				virtual bool AddWhiteList(const std::string& key, const std::string& listJson);

			private:
				std::map<std::string, std::string> m_listMap;
				mutable std::mutex m_listMapMutex;
			};
		}
	}
}
