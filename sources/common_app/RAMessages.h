#pragma once

#include <string>

#include <json/json.h>

class RAMessages
{
public:
	RAMessages() {}
	RAMessages(const std::string& senderID) :
		m_senderID(senderID),
		m_isValid(true)
	{}

	RAMessages(Json::Value& msg)
	{
		if (msg.isMember("MsgType")
			&& msg.isMember("Sender")
			&& msg["MsgType"].isString()
			&& msg["Sender"].isString()
			&& msg["MsgType"].asString() == "RA")
		{
			m_senderID = msg["Sender"].asString();
			m_isValid = true;
		}
		else
		{
			m_isValid = false;
		}
	}

	~RAMessages() {}

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
		outJson["MsgType"] = "RA";
		outJson["MsgSubType"] = GetMessgaeSubTypeStr();
		outJson["Sender"] = m_senderID;

		return outJson;
	}

	bool m_isValid;

private:
	std::string m_senderID;

};