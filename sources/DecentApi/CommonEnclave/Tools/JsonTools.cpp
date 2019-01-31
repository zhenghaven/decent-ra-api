#include "../../Common/Tools/JsonTools.h"

#include <string>
#include <cstring>

#include <rapidjson/document.h>
//#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "../../Common/Common.h"

using namespace Decent;

namespace
{
	static JSON_EDITION::Value& ConstructIndex(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, rapidjson::Value& val)
	{
		if (!doc.IsObject())
		{
			doc.SetObject();
		}
		if (!doc.HasMember(index.c_str()))
		{
			doc.AddMember(rapidjson::Value().SetString(rapidjson::StringRef(index.c_str(), index.size()), doc.GetAllocator()),
				val, doc.GetAllocator());
		}
		else
		{
			doc[index.c_str()] = val;
		}

		return doc[index.c_str()];
	}
}

bool Tools::ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outDoc, const std::string& inStr)
{
	outDoc.Parse(inStr.c_str());
	rapidjson::ParseErrorCode errcode = outDoc.GetParseError();
	
	return errcode == rapidjson::ParseErrorCode::kParseErrorNone;
}

bool Tools::ParseStr2Json(JSON_EDITION::JSON_DOCUMENT_TYPE& outDoc, const char* inStr)
{
	outDoc.Parse(inStr);
	rapidjson::ParseErrorCode errcode = outDoc.GetParseError();

	return errcode == rapidjson::ParseErrorCode::kParseErrorNone;
}

std::string Tools::Json2StyledString(const rapidjson::Value & inJson)
{
	rapidjson::StringBuffer buffer;
	//rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
	inJson.Accept(writer);

	std::string res(buffer.GetString());
	return res;
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, const std::string & val)
{
	return ConstructIndex(doc, index, 
		rapidjson::Value().SetString(rapidjson::StringRef(val.c_str(), val.size()), doc.GetAllocator()));
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, JSON_EDITION::Value & val)
{
	return ConstructIndex(doc, index, val);
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, const int val)
{
	return ConstructIndex(doc, index, rapidjson::Value().SetInt(val));
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, const double val)
{
	return ConstructIndex(doc, index, rapidjson::Value().SetDouble(val));
}

JSON_EDITION::Value& Tools::JsonSetVal(JSON_EDITION::JSON_DOCUMENT_TYPE& doc, const std::string & index, const bool val)
{
	return ConstructIndex(doc, index, rapidjson::Value().SetBool(val));
}
