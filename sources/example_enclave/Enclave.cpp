#include <initializer_list>
#include <vector>

#include <cppcodec/base64_rfc4648.hpp>

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "../common_enclave/enclave_tools.h"


#include <limits>


//Feature name        : Initializer lists
//Feature description : An object of type std::initializer_list<T> is a lightweight proxy object that provides access to an array of objects of type const T.
//Demo description    : Demonstrates the usage of initializer list in the constructor of an object in enclave.
class Number
{
public:
	Number(const std::initializer_list<int> &v) {
		for (auto i : v) {
			elements.push_back(i);
		}
	}

	void print_elements() {
		enclave_printf("[initializer_list] The elements of the vector are:");
		for (auto item : elements) {
			enclave_printf(" %d", item);
		}
		enclave_printf(".\n");
	}
private:
	std::vector<int> elements;
};

void ecall_initializer_list_demo()
{
	enclave_printf("[initializer_list] Using initializer list in the constructor. \n");
	Number m = { 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
	m.print_elements();

	enclave_printf("\n"); //end of demo
}

int ecall_add_two_int(int a, int b)
{
	int res = a + b;

	enclave_printf("Added %d, %d inside enclave as result of %d\n", a, b, res);

	return res;
}

void ecall_square_array(int* arr, const size_t len_in_byte)
{
	size_t len = len_in_byte / sizeof(int);
	for (int i = 0; i < len; ++i)
	{
		arr[i] *= arr[i];
	}

	std::string base64TestStr = "Base64 test string.";
	std::string base64CodeStr = cppcodec::base64_rfc4648::encode(base64TestStr.c_str(), base64TestStr.size());
	enclave_printf("base 64 code string: %s\n", base64CodeStr.c_str());
	auto base64out = cppcodec::base64_rfc4648::decode(base64CodeStr); ;
	enclave_printf("base 64 code string: %s\n", std::string((char*)base64out.data(), base64out.size()).c_str());

	const char* json = "{\"project\":\"rapidjson\",\"stars\":10}";
	rapidjson::Document d;
	d.Parse(json);
	rapidjson::Value& s = d["stars"];
	s.SetInt(s.GetInt() + 1);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	d.Accept(writer);

	enclave_printf("JSON Example: %s\n", buffer.GetString());

}
