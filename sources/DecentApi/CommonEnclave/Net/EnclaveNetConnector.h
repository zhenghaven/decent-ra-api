#pragma once

namespace Decent
{
	namespace Net
	{
		class EnclaveNetConnector
		{
		public:
			/** \brief	Default constructor */
			EnclaveNetConnector() :
				m_ptr(nullptr)
			{}

			EnclaveNetConnector(const EnclaveNetConnector& rhs) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			EnclaveNetConnector(EnclaveNetConnector&& rhs) :
				m_ptr(rhs.m_ptr)
			{
				rhs.m_ptr = nullptr;
			}

			/** \brief	Destructor */
			virtual ~EnclaveNetConnector()
			{}

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this object.
			 */
			EnclaveNetConnector& operator=(EnclaveNetConnector&& rhs)
			{
				if (this != &rhs)
				{
					void* tmp = this->m_ptr;
					this->m_ptr = rhs.m_ptr;
					rhs.m_ptr = tmp;
				}
				return *this;
			}

			/**
			 * \brief	Gets the connection pointer.
			 *
			 * \return	Connection pointer.
			 */
			void* Get() const
			{
				return m_ptr;
			}

		protected:
			void* m_ptr;
		};
	}
}
