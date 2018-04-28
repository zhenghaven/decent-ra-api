#include "LibExample.h"

#include <stdlib.h>
#include <stdio.h>

#include <iostream>
#include <vector>

#include <sgx_error.h>       /* sgx_status_t */
#include <sgx_eid.h>     /* sgx_enclave_id_t */

#include "Enclave_u.h"

/* OCall functions */
void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	* the input string to prevent buffer overflow.
	*/
	printf("%s", str);
}