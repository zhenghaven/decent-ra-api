#pragma once

#include "../../Messages.h"

#include <memory>
//#include <sgx_dh.h>

typedef struct _sgx_dh_msg1_t sgx_dh_msg1_t;
typedef struct _sgx_dh_msg2_t sgx_dh_msg2_t;
typedef struct _sgx_dh_msg3_t sgx_dh_msg3_t;

namespace Json
{
	class Value;
}

class SGXLAMessage : public Messages
{
public:
	static constexpr char const sk_LabelRoot[] = "SGXLA";
	static constexpr char const sk_LabelType[] = "Type";

	static constexpr char const sk_ValueCat[] = "SGXLA"; // = sk_LabelRoot;

	static std::string ParseType(const Json::Value& MsgRootContent);

public:
	SGXLAMessage() = delete;
	explicit SGXLAMessage(const std::string& senderID);
	explicit SGXLAMessage(const Json::Value& msg, const char* expectedType);
	virtual ~SGXLAMessage();

	virtual std::string GetMessageCategoryStr() const override;
	virtual std::string GetMessageTypeStr() const = 0;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const;

private:

};

class SGXLAErrMsg : public SGXLAMessage, public ErrorMessage
{
public:
	SGXLAErrMsg() = delete;
	SGXLAErrMsg(const std::string& senderID, const std::string& errStr);
	SGXLAErrMsg(const Json::Value& msg);
	virtual ~SGXLAErrMsg();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
};

class SGXLARequest : public SGXLAMessage
{
public:
	static constexpr char const sk_ValueType[] = "LAReq";

public:
	SGXLARequest() = delete;
	explicit SGXLARequest(const std::string& senderID);
	explicit SGXLARequest(const Json::Value& msg);
	virtual ~SGXLARequest();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
};

template<typename T>
class SGXLADataMessage : public SGXLAMessage
{
public:
	static constexpr char const sk_LabelData[] = "Data";

	static T* ParseData(const Json::Value& SGXLARoot);

public:
	SGXLADataMessage() = delete;
	SGXLADataMessage(const std::string& senderID, std::unique_ptr<T>& data) :
		SGXLAMessage(senderID),
		m_data(data.release())
	{}

	SGXLADataMessage(const Json::Value& msg, const char* expectedType) :
		SGXLAMessage(msg, expectedType),
		m_data(ParseData(msg[Messages::sk_LabelRoot][SGXLAMessage::sk_LabelRoot]))
	{}

	virtual ~SGXLADataMessage() {}

	const T& GetData() const { return *m_data; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	std::unique_ptr<const T> m_data;
};

class SGXLAMessage1 : public SGXLADataMessage<sgx_dh_msg1_t>
{
public:
	static constexpr char const sk_ValueType[] = "MSG1";

public:
	SGXLAMessage1() = delete;
	SGXLAMessage1(const std::string& senderID, std::unique_ptr<sgx_dh_msg1_t>& msg1Data);
	SGXLAMessage1(const Json::Value& msg);
	virtual ~SGXLAMessage1();

	virtual std::string GetMessageTypeStr() const override;
};

class SGXLAMessage2 : public SGXLADataMessage<sgx_dh_msg2_t>
{
public:
	static constexpr char const sk_ValueType[] = "MSG2";

public:
	SGXLAMessage2() = delete;
	SGXLAMessage2(const std::string& senderID, std::unique_ptr<sgx_dh_msg2_t>& msg2Data);
	SGXLAMessage2(const Json::Value& msg);
	virtual ~SGXLAMessage2();

	virtual std::string GetMessageTypeStr() const override;
};

class SGXLAMessage3 : public SGXLADataMessage<sgx_dh_msg3_t>
{
public:
	static constexpr char const sk_ValueType[] = "MSG3";

public:
	SGXLAMessage3() = delete;
	SGXLAMessage3(const std::string& senderID, std::unique_ptr<sgx_dh_msg3_t>& msg3Data);
	SGXLAMessage3(const Json::Value& msg);
	virtual ~SGXLAMessage3();

	virtual std::string GetMessageTypeStr() const override;
};
