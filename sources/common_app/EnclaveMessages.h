#pragma once

#include <string>

#include <json/json.h>

class EnclaveMessages
{
public:
	EnclaveMessages() {}
	EnclaveMessages(const std::string& senderID) :
		m_senderID(senderID),
		m_isValid(true)
	{}

	EnclaveMessages(Json::Value& msg)
	{
		if (msg.isMember("MsgType")
			&& msg.isMember("Sender")
			&& msg["MsgType"].isString()
			&& msg["Sender"].isString()
			&& msg["MsgType"].asString() == "Enclave")
		{
			m_senderID = msg["Sender"].asString();
			m_isValid = true;
		}
		else
		{
			m_isValid = false;
		}
	}

	~EnclaveMessages() {}

	virtual std::string GetMessgaeSubTypeStr() const = 0;

	virtual const std::string& GetSenderID() const
	{
		return m_senderID;
	}

	virtual bool IsValid() const
	{
		return m_isValid;
	}

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const
	{
		outJson["MsgType"] = "Enclave";
		outJson["MsgSubType"] = GetMessgaeSubTypeStr();
		outJson["Sender"] = m_senderID;

		return outJson;
	}

	bool m_isValid;

private:
	std::string m_senderID;

};