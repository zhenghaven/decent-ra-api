#include <tlibc/stdarg.h>
#include <tlibc/stdio.h>      /* vsnprintf */

#include <libc++/initializer_list>
#include <libc++/vector>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

void enclave_printf(const char * fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

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
