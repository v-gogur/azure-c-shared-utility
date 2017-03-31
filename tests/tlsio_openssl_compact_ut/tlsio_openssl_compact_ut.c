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

static bool on_io_open_complete_called;
static bool on_io_open_complete_context_ok;
static IO_OPEN_RESULT on_io_open_complete_result;
static bool on_io_error_called;
static bool on_io_error_context_ok;

#define IO_OPEN_COMPLETE_CONTEXT (void*)55
#define IO_ERROR_CONTEXT (void*)66
#define IO_BYTES_RECEIVED_CONTEXT (void*)77

static void reset_callback_context_records()
{
	on_io_open_complete_called = false;
	on_io_open_complete_context_ok = false;
	on_io_open_complete_result = -1;
	on_io_error_called = false;
	on_io_error_context_ok = false;
}

static void on_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
	on_io_open_complete_called = true;
	on_io_open_complete_result = open_result;
	on_io_open_complete_context_ok = context == IO_OPEN_COMPLETE_CONTEXT;
}

static void on_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
	context;
	buffer;
	size;
}

static void on_io_error(void* context)
{
	on_io_error_called = true;
	on_io_error_context_ok = context == IO_ERROR_CONTEXT;
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
int TLSv1_2_client_method() { return 0; }
void SSL_CTX_set_default_read_buffer_len(SSL_CTX* dummy, int dummy2) { dummy; dummy2; }
int SSL_shutdown(SSL* dummy) { dummy; return 0; }
void ThreadAPI_Sleep(unsigned int milliseconds) { milliseconds; return; }

#define SSL_Get_IPv4_OK (uint32_t)0x11223344
#define SSL_Get_IPv4_FAIL 0
#define SSL_Good_Ptr (void*)22
#define SSL_Good_Context_Ptr (SSL_CTX*)33
#define SSL_Good_Socket 44

 /**
  * You can create some global variables that your test will need in some way.
  */
static TLSIO_CONFIG tlsio_config = { .hostname = "fakehost.com",.port = 447 };

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
		
		//MOCKABLE_FUNCTION(, int, SSL_get_error, SSL*, ssl, int, lastReturn);
		//MOCKABLE_FUNCTION(, int, SSL_set_fd, SSL*, dummy, int, dummy2);
		//MOCKABLE_FUNCTION(, int, SSL_connect, SSL*, dummy);


		//MOCKABLE_FUNCTION(, int, SSL_write, SSL*, dummy, uint8_t*, buffer, size_t, size);
		//MOCKABLE_FUNCTION(, int, SSL_read, SSL*, dummy, uint8_t*, buffer, size_t, size);




		REGISTER_GLOBAL_MOCK_RETURNS(SSL_new, SSL_Good_Ptr, NULL);
		REGISTER_GLOBAL_MOCK_RETURNS(SSL_CTX_new, SSL_Good_Context_Ptr, NULL);
		REGISTER_GLOBAL_MOCK_RETURNS(SSL_set_fd, 1, 0);
		REGISTER_GLOBAL_MOCK_RETURNS(SSL_connect, 0, -1);
		;

        /**
         * Or you can combine, for example, in the success case malloc will call my_gballoc_malloc, and for
         *    the failed cases, it will return NULL.
         */
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
        REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
        //REGISTER_GLOBAL_MOCK_HOOK(gballoc_realloc, my_gballoc_realloc);
        //REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_realloc, NULL);
        REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

        /**
         * You can initialize other global variables here, for instance image that you have a standard void* that will be converted
         *   any pointer that your test needs.
         */
        //g_GenericPointer = malloc(1);
        //ASSERT_IS_NOT_NULL(g_GenericPointer);
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

	// This enum is defined here rather than at the top because it defines the behavior of the function directly below
	// and is used nowhere else. This is a list of all the possible fail points plus the happy path for a 
	// create/open/close/destroy sequence.
	enum 
	{ 
		FP_NULL_CONFIG,		// supplying a null tlsio config to create
		FP_DNS,				// DNS lookup fails
		FP_TLSIO_MALLOC,	// tlsio instance malloc fails
		// Create has succeeded here
		//FP_SOCKET,			// creation of the TLS socket fails

		FP_NONE
	};

// The messy macro on line 2 of FAIL_POINT is the expansion of STRICT_EXPECTED_CALL
#define FAIL_POINT(fp, call) if(fail_point >= fp) {  \
	C2(get_auto_ignore_args_function_, call)(C2(umock_c_strict_expected_,call), #call);			\
	fail_points[fp] = expected_call_count;	\
	expected_call_count++;		\
}

	/* Tests_SRS_TEMPLATE_21_001: [ The target_create shall call callee_open to do stuff and allocate the memory. ]*/
	TEST_FUNCTION(tlsio_openssl_create_and_open)
	{
		// fail_points is a lookup table that provides an index 
		// to pass to umock_c_negative_tests_fail_call(0) given
		// a provided fail point enum value. If the index is 255,
		// that means don't call umock_c_negative_tests_fail_call().
		uint16_t fail_points[FP_NONE + 1];
		uint16_t expected_call_count = 0;


		for (int fail_point = 0; fail_point <= FP_NONE; fail_point++)
		{
			///arrange
			reset_callback_context_records();
			umock_c_reset_all_calls();

			expected_call_count = 0;
			memset(fail_points, 0xff, sizeof(fail_points));

			int negativeTestsInitResult = umock_c_negative_tests_init();
			ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);


			// Create
			FAIL_POINT(FP_DNS, SSL_Get_IPv4(IGNORED_NUM_ARG));
			FAIL_POINT(FP_TLSIO_MALLOC, gballoc_malloc(IGNORED_NUM_ARG));
			//if (fail_point >= FP_DNS)
			//{ 
			//	STRICT_EXPECTED_CALL(SSL_Get_IPv4(IGNORED_NUM_ARG)); 
			//	fail_points[FP_DNS] = expected_call_count;
			//	expected_call_count++;
			//}
			//if (fail_point >= FP_TLSIO_MALLOC)	
			//{ 
			//	STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)); 
			//	fail_points[FP_DNS] = expected_call_count;
			//	expected_call_count++;
			//}

			// Open
			//if (i >= FP_SOCKET)			{ STRICT_EXPECTED_CALL(SSL_Socket_Create(IGNORED_NUM_ARG, IGNORED_NUM_ARG)); }

#if(false)
			STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_NUM_ARG));
			STRICT_EXPECTED_CALL(SSL_new(SSL_Good_Context_Ptr));
			STRICT_EXPECTED_CALL(SSL_set_fd(SSL_Good_Ptr, SSL_Good_Socket));
			STRICT_EXPECTED_CALL(SSL_connect(SSL_Good_Ptr));

			// Destroy SSL Connection Members
			STRICT_EXPECTED_CALL(SSL_free(SSL_Good_Ptr));
			STRICT_EXPECTED_CALL(SSL_CTX_free(SSL_Good_Context_Ptr));
			STRICT_EXPECTED_CALL(SSL_Socket_Close(SSL_Good_Socket));
#endif
			if (fail_point > FP_TLSIO_MALLOC)
			{
				// Destroy
				STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG));      //This is the free of TLS_IO_INSTANCE.
			}


			umock_c_negative_tests_snapshot();

			umock_c_negative_tests_reset();

			uint16_t fail_index = fail_points[fail_point];
			if (fail_index != 0xffff)
			{
				umock_c_negative_tests_fail_call(fail_index);
			}


			///act

			const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

			TLSIO_CONFIG* cfg = fail_point == FP_NULL_CONFIG ? NULL : &tlsio_config;
			CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(cfg);

			if (fail_point <= FP_TLSIO_MALLOC)
			{
				ASSERT_IS_NULL(tlsio);
			}

			if (tlsio)
			{
				//int open_result = tlsio_id->concrete_io_open(tlsio, on_io_open_complete, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received,
				//	IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);
				//open_result;

				//ASSERT_IS_FALSE(on_io_error_called);
				//ASSERT_IS_TRUE(on_io_open_complete_called);
				//ASSERT_IS_TRUE(on_io_open_complete_context_ok);
				//ASSERT_ARE_EQUAL(int, IO_OPEN_OK, on_io_open_complete_result);

				tlsio_id->concrete_io_destroy(tlsio);
			}


			///assert


			/**
			* The follow assert will compare the expected calls with the actual calls. If it is different,
			*    it will show the serialized strings with the differences in the log.
			*/
			ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

			///cleanup
			umock_c_negative_tests_deinit();

		}
	}

END_TEST_SUITE(tlsio_openssl_compact_unittests)
