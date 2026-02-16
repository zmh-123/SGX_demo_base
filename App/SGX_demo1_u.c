#include "SGX_demo1_u.h"
#include <errno.h>

typedef struct ms_encrypt_message_t {
	sgx_status_t ms_retval;
	const char* ms_str;
	size_t ms_str_len;
	uint8_t* ms_output_cipher;
	uint8_t* ms_output_mac;
	size_t ms_len;
} ms_encrypt_message_t;

typedef struct ms_decrypt_message_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_cipher;
	size_t ms_len;
	const uint8_t* ms_mac;
	char* ms_output_str;
} ms_decrypt_message_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL SGX_demo1_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SGX_demo1_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SGX_demo1_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SGX_demo1_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SGX_demo1_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[5];
} ocall_table_SGX_demo1 = {
	5,
	{
		(void*)(uintptr_t)SGX_demo1_sgx_oc_cpuidex,
		(void*)(uintptr_t)SGX_demo1_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)SGX_demo1_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)SGX_demo1_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)SGX_demo1_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t encrypt_message(sgx_enclave_id_t eid, sgx_status_t* retval, const char* str, uint8_t* output_cipher, uint8_t* output_mac, size_t len)
{
	sgx_status_t status;
	ms_encrypt_message_t ms;
	ms.ms_str = str;
	ms.ms_str_len = str ? strlen(str) + 1 : 0;
	ms.ms_output_cipher = output_cipher;
	ms.ms_output_mac = output_mac;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_SGX_demo1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_message(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* cipher, size_t len, const uint8_t* mac, char* output_str)
{
	sgx_status_t status;
	ms_decrypt_message_t ms;
	ms.ms_cipher = cipher;
	ms.ms_len = len;
	ms.ms_mac = mac;
	ms.ms_output_str = output_str;
	status = sgx_ecall(eid, 1, &ocall_table_SGX_demo1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

