// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#endif

/**
 * The gballoc.h will replace the malloc, free, and realloc by the my_gballoc functions, in this case,
 *    if you define these mock functions after include the gballoc.h, you will create an infinity recursion,
 *    so, places the my_gballoc functions before the #include "azure_c_shared_utility/gballoc.h"
 */
void* my_gballoc_malloc(size_t size)
{
	return malloc(size);
}

void* my_gballoc_realloc(void* ptr, size_t size)
{
	return realloc(ptr, size);
}

void my_gballoc_free(void* ptr)
{
	free(ptr);
}

/**
 * Include the C standards here.
 */
#ifdef __cplusplus
#include <cstddef>
#include <ctime>
#else
#include <stddef.h>
#include <time.h>
#endif

/**
 * Include the test tools.
 */
#include "testrunnerswitcher.h"
#include "umock_c.h"
#include "umocktypes_charptr.h"
#include "umock_c_negative_tests.h"
#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/xio.h"

// Keep track of whether callbacks were performed as expected
static bool on_io_open_complete_call_count;
static bool on_io_open_complete_context_ok;
static IO_OPEN_RESULT on_io_open_complete_result;
static int on_io_error_call_count;
static bool on_io_error_context_ok;
static int on_io_close_call_count;
static bool on_io_close_context_ok;

#define IO_OPEN_COMPLETE_CONTEXT (void*)55
#define IO_ERROR_CONTEXT (void*)66
#define IO_BYTES_RECEIVED_CONTEXT (void*)77
#define IO_CLOSE_COMPLETE_CONTEXT (void*)66

static void reset_callback_context_records()
{
	on_io_open_complete_call_count = 0;
	on_io_open_complete_context_ok = false;
	on_io_open_complete_result = -1;
	on_io_error_call_count = 0;
	on_io_error_context_ok = false;
	on_io_close_call_count = 0;
}

static void on_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
	on_io_open_complete_call_count++;
	on_io_open_complete_result = open_result;
	on_io_open_complete_context_ok = context == IO_OPEN_COMPLETE_CONTEXT;
}

static void on_io_close_complete(void* context)
{
	on_io_close_call_count++;
	on_io_close_context_ok = context == IO_CLOSE_COMPLETE_CONTEXT;
}

static void on_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
	context;
	buffer;
	size;
}

static void on_io_error(void* context)
{
	on_io_error_call_count = true;
	on_io_error_context_ok = context == IO_ERROR_CONTEXT;
}

static void ASSERT_ERROR_CALLBACK_COUNT(int count)
{
	ASSERT_ARE_EQUAL_WITH_MSG(int, count, on_io_error_call_count, "io_error_callback count mismatch");
	if (count > 0)
	{
		ASSERT_IS_TRUE_WITH_MSG(on_io_error_context_ok, "io_error_callback missing context");
	}
}

static void ASSERT_IO_OPEN_CALLBACK(bool called, int open_result)
{
	if (called)
	{
		ASSERT_ARE_EQUAL_WITH_MSG(int, 1, on_io_open_complete_call_count, "on_io_open_complete_callback count mismatch");
		ASSERT_ARE_EQUAL_WITH_MSG(int, on_io_open_complete_result, open_result, "on_io_open_complete result mismatch");
		ASSERT_IS_TRUE_WITH_MSG(on_io_open_complete_context_ok, "io_open_complete_context not passed");
	}
	else
	{
		ASSERT_ARE_EQUAL_WITH_MSG(int, 0, on_io_open_complete_call_count, "unexpected on_io_open_complete_callback");
	}
}

static void ASSERT_IO_CLOSE_CALLBACK(bool called)
{
	if (called)
	{
		ASSERT_ARE_EQUAL_WITH_MSG(int, 1, on_io_close_call_count, "on_io_close_complete_callback count mismatch");
		ASSERT_IS_TRUE_WITH_MSG(on_io_close_context_ok, "io_close_complete_context not passed");
	}
	else
	{
		ASSERT_ARE_EQUAL_WITH_MSG(int, 0, on_io_close_call_count, "unexpected on_io_close_complete_callback");
	}
}

/**
 * Include the mockable headers here.
 * These are the headers that contains the functions that you will replace to execute the test.
 *
 * For instance, if you will test a target_create() function in the target.c that calls a callee_open() function 
 *   in the callee.c, you must define callee_open() as a mockable function in the callee.h.
 *
 * Observe that we will replace the functions in callee.h here, so we don't care about its real implementation,
 *   in fact, on this example, we even have the callee.c.
 *
 * Include all header files that you will replace the mockable functions in the ENABLE_MOCKS session below.
 *
 */
#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/ssl_socket.h"
#include "openssl/ssl.h"
#undef ENABLE_MOCKS

// These functions must be available to call, but they have no effect
// on 
int TLSv1_2_client_method() { return 0; }
void SSL_CTX_set_default_read_buffer_len(SSL_CTX* dummy, int dummy2) { dummy; dummy2; }
void ThreadAPI_Sleep(unsigned int milliseconds) { milliseconds; return; }

#include "ssl_errors.c"

#include "test_points.c"

 /**
  * You can create some global variables that your test will need in some way.
  */
static TLSIO_CONFIG tlsio_config = { .port = SSL_goood_port_number };

 /**
  * Umock error will helps you to identify errors in the test suite or in the way that you are 
  *    using it, just keep it as is.
  */
DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s", ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

/**
 * This is necessary for the test suite, just keep as is.
 */
static TEST_MUTEX_HANDLE g_testByTest;
static TEST_MUTEX_HANDLE g_dllByDll;

/**
 * Tests begin here. Give a name for your test, for instance template_ut, use the same 
 *   name to close the test suite on END_TEST_SUITE(template_empty_ut), and to identify the  
 *   test suit in the main() function 
 *   
 *   RUN_TEST_SUITE(template_empty_ut, failedTestCount);
 *
 */
BEGIN_TEST_SUITE(tlsio_openssl_compact_unittests)

    /**
     * This is the place where we initialize the test system. Replace the test name to associate the test 
     *   suite with your test cases.
     * It is called once, before start the tests.
     */
    TEST_SUITE_INITIALIZE(a)
    {
        int result;
        TEST_INITIALIZE_MEMORY_DEBUG(g_dllByDll);
        g_testByTest = TEST_MUTEX_CREATE();
        ASSERT_IS_NOT_NULL(g_testByTest);

        (void)umock_c_init(on_umock_c_error);

        result = umocktypes_charptr_register_types();
		ASSERT_ARE_EQUAL(int, 0, result);

        /**
         * It is necessary to identify the types defined on your target. With it, the test system will 
         *    know how to use it. 
         *
         * On the target.h example, there is the type TARGET_HANDLE that is a void*
         */
        REGISTER_UMOCK_ALIAS_TYPE(SSL, void*);
        REGISTER_UMOCK_ALIAS_TYPE(SSL_CTX, void*);
		REGISTER_UMOCK_ALIAS_TYPE(uint32_t, unsigned int);

		REGISTER_GLOBAL_MOCK_RETURNS(SSL_Get_IPv4, SSL_Get_IPv4_OK, SSL_Get_IPv4_FAIL);
		REGISTER_GLOBAL_MOCK_RETURNS(SSL_Socket_Create, SSL_Good_Socket, -1);

		REGISTER_GLOBAL_MOCK_RETURNS(SSL_new, SSL_Good_Ptr, NULL);
		REGISTER_GLOBAL_MOCK_RETURNS(SSL_CTX_new, SSL_Good_Context_Ptr, NULL);
		REGISTER_GLOBAL_MOCK_RETURNS(SSL_set_fd, 1, 0);
		REGISTER_GLOBAL_MOCK_HOOK(SSL_connect, my_SSL_connect);

        /**
         * Or you can combine, for example, in the success case malloc will call my_gballoc_malloc, and for
         *    the failed cases, it will return NULL.
         */
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

        /**
         * You can initialize other global variables here, for instance image that you have a standard void* that will be converted
         *   any pointer that your test needs.
         */
        //g_GenericPointer = malloc(1);
        //ASSERT_IS_NOT_NULL(g_GenericPointer);
		tlsio_config.hostname = SSL_goood_host_name;
    }

    /**
     * The test suite will call this function to cleanup your machine.
     * It is called only once, after all tests is done.
     */
    TEST_SUITE_CLEANUP(TestClassCleanup)
    {
        //free(g_GenericPointer);

        umock_c_deinit();

        TEST_MUTEX_DESTROY(g_testByTest);
        TEST_DEINITIALIZE_MEMORY_DEBUG(g_dllByDll);
    }

    /**
     * The test suite will call this function to prepare the machine for the new test.
     * It is called before execute each test.
     */
    TEST_FUNCTION_INITIALIZE(initialize)
    {
        if (TEST_MUTEX_ACQUIRE(g_testByTest))
        {
            ASSERT_FAIL("Could not acquire test serialization mutex.");
        }

        umock_c_reset_all_calls();
        
        //my_callee_open_must_succeed = true; //As default, callee_open will return a valid pointer.
    }

    /**
     * The test suite will call this function to cleanup your machine for the next test.
     * It is called after execute each test.
     */
    TEST_FUNCTION_CLEANUP(cleans)
    {
        TEST_MUTEX_RELEASE(g_testByTest);
    }




	/* Tests_SRS_TEMPLATE_21_001: [ The target_create shall call callee_open to do stuff and allocate the memory. ]*/
	TEST_FUNCTION(tlsio_openssl_main_sequence)
	{

		for (int test_point = 0; test_point <= TP_FINAL_OK; test_point++)
		{
			/////////////////////////////////////////////////////////////////////////////
			///arrange
			/////////////////////////////////////////////////////////////////////////////
			reset_callback_context_records();
			umock_c_reset_all_calls();

			InitTestPoints();

			int negativeTestsInitResult = umock_c_negative_tests_init();
			ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);


			// Create
			TEST_POINT(TP_DNS_FAIL, SSL_Get_IPv4(SSL_goood_host_name));
			TEST_POINT(TP_TLSIO_MALLOC_FAIL, gballoc_malloc(IGNORED_NUM_ARG));

			// Open
			TEST_POINT(TP_SOCKET_OPEN_FAIL, SSL_Socket_Create(SSL_Get_IPv4_OK, SSL_goood_port_number));
			TEST_POINT(TP_SSL_CTX_new_FAIL, SSL_CTX_new(IGNORED_NUM_ARG));
			TEST_POINT(TP_SSL_new_FAIL, SSL_new(SSL_Good_Context_Ptr));
			TEST_POINT(TP_SSL_set_fd_FAIL, SSL_set_fd(SSL_Good_Ptr, SSL_Good_Socket));

			// SSL_connect can succeed and fail in several different sequences
			if (test_point >= TP_SSL_connect_0_FAIL)
			{
				switch (test_point)
				{
				case TP_SSL_connect_0_FAIL:
					SSL_ERROR_PREPARE_SEQUENCE(SSL_CONNECT_ERROR_SEQUENCE_0);
					NO_FAIL_TEST_POINT(TP_SSL_connect_0_FAIL, SSL_connect(SSL_Good_Ptr));
					break;
				case TP_SSL_connect_1_FAIL:
					SSL_ERROR_PREPARE_SEQUENCE(SSL_CONNECT_ERROR_SEQUENCE_1);
					NO_FAIL_TEST_POINT(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
					NO_FAIL_TEST_POINT(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
					NO_FAIL_TEST_POINT(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
					break;
				case TP_SSL_connect_0_OK:
					SSL_ERROR_PREPARE_SEQUENCE(SSL_CONNECT_OK_ERROR_SEQUENCE_0);
					NO_FAIL_TEST_POINT(TP_SSL_connect_0_OK, SSL_connect(SSL_Good_Ptr));
					break;
				default:
					SSL_ERROR_PREPARE_SEQUENCE(SSL_CONNECT_OK_ERROR_SEQUENCE_1);
					NO_FAIL_TEST_POINT(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
					NO_FAIL_TEST_POINT(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
					NO_FAIL_TEST_POINT(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
					break;
				}
			}




			// Destroy SSL Connection Members
			IF_PAST_TEST_POINT(TP_SSL_connect_1_FAIL, SSL_shutdown(SSL_Good_Ptr));
			IF_PAST_TEST_POINT(TP_SSL_new_FAIL, SSL_free(SSL_Good_Ptr));
			IF_PAST_TEST_POINT(TP_SSL_CTX_new_FAIL, SSL_CTX_free(SSL_Good_Context_Ptr));
			IF_PAST_TEST_POINT(TP_SOCKET_OPEN_FAIL, SSL_Socket_Close(SSL_Good_Socket));
			// Destroy
			IF_PAST_TEST_POINT(TP_TLSIO_MALLOC_FAIL, gballoc_free(IGNORED_PTR_ARG));      //This is the free of TLS_IO_INSTANCE.


			umock_c_negative_tests_snapshot();

			umock_c_negative_tests_reset();

			// Each test pass has no more than one place where umock_c_negative_tests_fail_call 
			// will force a failure.   
			uint16_t fail_index = test_points[test_point];
			if (fail_index != 0xffff)
			{
				umock_c_negative_tests_fail_call(fail_index);
			}

			// Show the fail point description in the output for the sake of 
			// human readability
			test_point_label_output(test_point);

			//////////////////////////////////////////////////////////////////////////////////////////////////////
			///act
			//////////////////////////////////////////////////////////////////////////////////////////////////////

			const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

			TLSIO_CONFIG* cfg = test_point == TP_NULL_CONFIG_FAIL ? NULL : &tlsio_config;
			CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(cfg);

			if (test_point <= TP_TLSIO_MALLOC_FAIL)
			{
				ASSERT_IS_NULL(tlsio);
			}

			if (tlsio)
			{
				ON_IO_OPEN_COMPLETE open_callback = test_point != TP_Open_no_callback ? on_io_open_complete : NULL;
				ASSERT_IO_OPEN_CALLBACK(false, 0);
				int open_result = tlsio_id->concrete_io_open(tlsio, open_callback, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received,
					IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);
				// TODO: Add asserts for open_result plus callbacks
				SSL_ERROR_ASSERT_LAST_ERROR_SEQUENCE();	// special checking for SSL_connect
				if (test_point >= TP_SSL_connect_0_OK)
				{
					// Here the open succeeded
					ASSERT_ARE_EQUAL_WITH_MSG(int, 0, open_result, "Unexpected concrete_io_open failure");
					ASSERT_ERROR_CALLBACK_COUNT(0);
					ASSERT_IO_OPEN_CALLBACK(test_point != TP_Open_no_callback, IO_OPEN_OK);
				}
				else
				{
					// Here the open failed
					ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, open_result, "Unexpected concrete_io_open success");
					ASSERT_ERROR_CALLBACK_COUNT(1);
					ASSERT_IO_OPEN_CALLBACK(true, IO_OPEN_ERROR);
				}

				// Close here
				// TODO:  close
				ON_IO_CLOSE_COMPLETE close_callback = test_point != TP_Close_no_callback ? on_io_close_complete : NULL;
				tlsio_id->concrete_io_close(tlsio, close_callback, IO_CLOSE_COMPLETE_CONTEXT);
				ASSERT_IO_CLOSE_CALLBACK(test_point != TP_Close_no_callback);

				tlsio_id->concrete_io_destroy(tlsio);
			}

			/////////////////////////////////////////////////////////////////////////////////////////////////////
			///assert
			/////////////////////////////////////////////////////////////////////////////////////////////////////


			/**
			* The follow assert will compare the expected calls with the actual calls. If it is different,
			*    it will show the serialized strings with the differences in the log.
			*/
			ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

			///cleanup
			umock_c_negative_tests_deinit();

		}
	}

	/* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
	TEST_FUNCTION(tlsio_openssl_create__tlsio_get_interface_description)
	{
		///act
		const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

		///assert
		/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_001: [ The tlsio_openssl_compact shall implement and export all the Concrete functions in the VTable IO_INTERFACE_DESCRIPTION defined in the xio.h. ] */
		// Later specific tests will verify the identity of each function
		ASSERT_IS_NOT_NULL(tlsio_id->concrete_io_close);
		ASSERT_IS_NOT_NULL(tlsio_id->concrete_io_create);
		ASSERT_IS_NOT_NULL(tlsio_id->concrete_io_destroy);
		ASSERT_IS_NOT_NULL(tlsio_id->concrete_io_dowork);
		ASSERT_IS_NOT_NULL(tlsio_id->concrete_io_open);
		ASSERT_IS_NOT_NULL(tlsio_id->concrete_io_retrieveoptions);
		ASSERT_IS_NOT_NULL(tlsio_id->concrete_io_send);
		ASSERT_IS_NOT_NULL(tlsio_id->concrete_io_setoption);
	}

END_TEST_SUITE(tlsio_openssl_compact_unittests)
