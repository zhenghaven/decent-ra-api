#include "SGXLAMessage.h"

#include <json/json.h>

#include <sgx_dh.h>

#include "../../../common/DataCoding.h"
#include "../../MessageException.h"

constexpr char SGXLAMessage::sk_LabelRoot[];
constexpr char SGXLAMessage::sk_LabelType[];
constexpr char SGXLAMessage::sk_ValueCat[];

std::string SGXLAMessage::ParseType(const Json::Value & MsgRootContent)
{
	if (MsgRootContent.isMember(SGXLAMessage::sk_LabelRoot) && MsgRootContent[SGXLAMessage::sk_LabelRoot].isObject() &&
		MsgRootContent[SGXLAMessage::sk_LabelRoot].isMember(sk_LabelType) && MsgRootContent[SGXLAMessage::sk_LabelRoot][sk_LabelType].isString()
		)
	{
		return MsgRootContent[SGXLAMessage::sk_LabelRoot][sk_LabelType].asString();
	}
	throw MessageParseException();
}

SGXLAMessage::SGXLAMessage(const std::string & senderID) :
	Messages(senderID)
{
}

SGXLAMessage::SGXLAMessage(const Json::Value & msg, const char * expectedType) :
	Messages(msg, sk_ValueCat)
{
	if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
	{
		throw MessageParseException();
	}
}

SGXLAMessage::~SGXLAMessage()
{
}

std::string SGXLAMessage::GetMessageCategoryStr() const
{
	return SGXLAMessage::sk_ValueCat;
}

Json::Value & SGXLAMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[SGXLAMessage::sk_LabelRoot] = Json::objectValue;
	parent[SGXLAMessage::sk_LabelRoot][SGXLAMessage::sk_LabelType] = GetMessageTypeStr();

	return parent[SGXLAMessage::sk_LabelRoot];
}

SGXLAErrMsg::SGXLAErrMsg(const std::string & senderID, const std::string & errStr) :
	SGXLAMessage(senderID),
	ErrorMessage(errStr)
{
}

SGXLAErrMsg::SGXLAErrMsg(const Json::Value & msg) :
	SGXLAMessage(msg, sk_ValueType),
	ErrorMessage(msg[Messages::sk_LabelRoot][SGXLAMessage::sk_LabelRoot])
{
}

SGXLAErrMsg::~SGXLAErrMsg()
{
}

std::string SGXLAErrMsg::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & SGXLAErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXLAMessage::GetJsonMsg(outJson);

	//parent[SGXLAErrMsg::sk_LabelType] = sk_ValueType;
	parent[sk_LabelErrMsg] = GetErrorStr();

	return parent;
}

constexpr char SGXLARequest::sk_ValueType[];

SGXLARequest::SGXLARequest(const std::string & senderID) :
	SGXLAMessage(senderID)
{
}

SGXLARequest::SGXLARequest(const Json::Value & msg) :
	SGXLAMessage(msg, sk_ValueType)
{
}

SGXLARequest::~SGXLARequest()
{
}

std::string SGXLARequest::GetMessageTypeStr() const
{
	return sk_ValueType;
}

Json::Value & SGXLARequest::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXLAMessage::GetJsonMsg(outJson);

	//parent[SGXLARequest::sk_LabelType] = sk_ValueType;

	return parent;
}

template<typename T>
static inline T* ParseDataTemplate(const Json::Value & SGXLARoot, const char* labelData)
{
	if (SGXLARoot.isMember(labelData) && SGXLARoot[labelData].isString())
	{
		T* dataPtr = new T;
		DeserializeStruct(*dataPtr, SGXLARoot[labelData].asString());
		return dataPtr;
	}
	throw MessageParseException();
}

constexpr char SGXLADataMessage<sgx_dh_msg1_t>::sk_LabelData[];
constexpr char SGXLADataMessage<sgx_dh_msg2_t>::sk_LabelData[];
constexpr char SGXLADataMessage<sgx_dh_msg3_t>::sk_LabelData[];

inline sgx_dh_msg1_t * SGXLADataMessage<sgx_dh_msg1_t>::ParseData(const Json::Value & SGXLARoot)
{
	return ParseDataTemplate<sgx_dh_msg1_t>(SGXLARoot, sk_LabelData);
}

inline sgx_dh_msg2_t * SGXLADataMessage<sgx_dh_msg2_t>::ParseData(const Json::Value & SGXLARoot)
{
	return ParseDataTemplate<sgx_dh_msg2_t>(SGXLARoot, sk_LabelData);
}

inline sgx_dh_msg3_t * SGXLADataMessage<sgx_dh_msg3_t>::ParseData(const Json::Value & SGXLARoot)
{
	return ParseDataTemplate<sgx_dh_msg3_t>(SGXLARoot, sk_LabelData);
}

inline Json::Value & SGXLADataMessage<sgx_dh_msg1_t>::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXLAMessage::GetJsonMsg(outJson);
	parent[sk_LabelData] = SerializeStruct(*m_data);
	return parent;
}

inline Json::Value & SGXLADataMessage<sgx_dh_msg2_t>::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXLAMessage::GetJsonMsg(outJson);
	parent[sk_LabelData] = SerializeStruct(*m_data);
	return parent;
}

inline Json::Value & SGXLADataMessage<sgx_dh_msg3_t>::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXLAMessage::GetJsonMsg(outJson);
	parent[sk_LabelData] = SerializeStruct(*m_data);
	return parent;
}

constexpr char SGXLAMessage1::sk_ValueType[];

SGXLAMessage1::SGXLAMessage1(const std::string & senderID, std::unique_ptr<sgx_dh_msg1_t>& msg1Data) :
	SGXLADataMessage(senderID, msg1Data)
{
}

SGXLAMessage1::SGXLAMessage1(const Json::Value & msg) :
	SGXLADataMessage(msg, sk_ValueType)
{
}

SGXLAMessage1::~SGXLAMessage1()
{
}

std::string SGXLAMessage1::GetMessageTypeStr() const
{
	return sk_ValueType;
}

constexpr char SGXLAMessage2::sk_ValueType[];

SGXLAMessage2::SGXLAMessage2(const std::string & senderID, std::unique_ptr<sgx_dh_msg2_t>& msg2Data) :
	SGXLADataMessage(senderID, msg2Data)
{
}

SGXLAMessage2::SGXLAMessage2(const Json::Value & msg) :
	SGXLADataMessage(msg, sk_ValueType)
{
}

SGXLAMessage2::~SGXLAMessage2()
{
}

std::string SGXLAMessage2::GetMessageTypeStr() const
{
	return sk_ValueType;
}

constexpr char SGXLAMessage3::sk_ValueType[];

SGXLAMessage3::SGXLAMessage3(const std::string & senderID, std::unique_ptr<sgx_dh_msg3_t>& msg3Data) :
	SGXLADataMessage(senderID, msg3Data)
{
}

SGXLAMessage3::SGXLAMessage3(const Json::Value & msg) :
	SGXLADataMessage(msg, sk_ValueType)
{
}

SGXLAMessage3::~SGXLAMessage3()
{
}

std::string SGXLAMessage3::GetMessageTypeStr() const
{
	return sk_ValueType;
}
