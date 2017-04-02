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

static int on_io_send_complete_call_count;
static bool on_io_send_complete_context_ok;
static IO_SEND_RESULT on_io_send_complete_result;

#define IO_OPEN_COMPLETE_CONTEXT (void*)55
#define IO_ERROR_CONTEXT (void*)66
#define IO_BYTES_RECEIVED_CONTEXT (void*)77
#define IO_CLOSE_COMPLETE_CONTEXT (void*)66
#define IO_SEND_COMPLETE_CONTEXT (void*)7658

static void reset_callback_context_records()
{
    on_io_open_complete_call_count = 0;
    on_io_open_complete_context_ok = false;
    on_io_open_complete_result = -1;
    on_io_error_call_count = 0;
    on_io_error_context_ok = false;
    on_io_close_call_count = 0;
    on_io_close_context_ok = false;
    on_io_send_complete_call_count = 0;
    on_io_send_complete_context_ok = false;
    on_io_send_complete_result = -1;
}

/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
/* Tests_SRS_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
static void on_io_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
    bool result_valid = open_result == IO_OPEN_OK || open_result == IO_OPEN_ERROR;
    ASSERT_IS_TRUE_WITH_MSG(result_valid, "Invalid IO_OPEN_RESULT");
    on_io_open_complete_call_count++;
    on_io_open_complete_result = open_result;
    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_028: [ If tlsio_openssl_compact_open calls on_io_open_complete, it shall always pass the provided on_io_open_complete_context parameter. ]*/
    on_io_open_complete_context_ok = context == IO_OPEN_COMPLETE_CONTEXT;
}

/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
/* Tests_SRS_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_041: [ The tlsio_openssl_compact_send shall call the provided on_send_complete callback function. ]*/
/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_042: [ The tlsio_openssl_compact_send shall supply the provided callback_context when it calls on_send_complete. ]*/
static void on_io_send_complete(void* context, IO_SEND_RESULT send_result)
{
    on_io_send_complete_call_count++;
    on_io_send_complete_context_ok = context == IO_SEND_COMPLETE_CONTEXT;
    on_io_send_complete_result = send_result;
}

/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
/* Tests_SRS_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_037: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall call on_io_close_complete. ] */
/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_038: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall pass the callback_context handle into the on_io_close_complete call. ] */
static void on_io_close_complete(void* context)
{
    on_io_close_call_count++;
    on_io_close_context_ok = context == IO_CLOSE_COMPLETE_CONTEXT;
}

/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
/* Tests_SRS_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
static void on_bytes_received(void* context, const unsigned char* buffer, size_t size)
{
    context;
    buffer;
    size;
}

/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_004: [ The tlsio_openssl_compact shall call the callbacks functions defined in the xio.h ]*/
/* Tests_SRS_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
static void on_io_error(void* context)
{
    on_io_error_call_count = true;
    on_io_error_context_ok = context == IO_ERROR_CONTEXT;
}

static void ASSERT_IO_ERROR_CALLBACK(bool called)
{
    int count = called ? 1 : 0;
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

static void ASSERT_IO_SEND_CALLBACK(bool called, int open_result)
{
    if (called)
    {
        ASSERT_ARE_EQUAL_WITH_MSG(int, 1, on_io_send_complete_call_count, "on_io_send_complete_callback count mismatch");
        ASSERT_ARE_EQUAL_WITH_MSG(int, on_io_send_complete_result, open_result, "on_io_send_complete result mismatch");
        ASSERT_IS_TRUE_WITH_MSG(on_io_send_complete_context_ok, "io_send_complete_context not passed");
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
        REGISTER_GLOBAL_MOCK_HOOK(SSL_write, my_SSL_write);

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
            umock_c_reset_all_calls();

            InitTestPoints();

            int negativeTestsInitResult = umock_c_negative_tests_init();
            ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);


            // Create
            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_015: [ If the IP for the hostName cannot be found, tlsio_openssl_compact_create shall return NULL. ]*/
            TEST_POINT(TP_DNS_FAIL, SSL_Get_IPv4(SSL_goood_host_name));
            TEST_POINT(TP_TLSIO_MALLOC_FAIL, gballoc_malloc(IGNORED_NUM_ARG));

            // Handle options


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
                    SSL_CONNECT_ERROR_PREPARE_SEQUENCE(SSL_CONNECT_FAIL_ERROR_SEQUENCE_0);
                    NO_FAIL_TEST_POINT(TP_SSL_connect_0_FAIL, SSL_connect(SSL_Good_Ptr));
                    break;
                case TP_SSL_connect_1_FAIL:
                    SSL_CONNECT_ERROR_PREPARE_SEQUENCE(SSL_CONNECT_FAIL_ERROR_SEQUENCE_1);
                    NO_FAIL_TEST_POINT(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
                    NO_FAIL_TEST_POINT(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
                    NO_FAIL_TEST_POINT(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
                    break;
                case TP_SSL_connect_0_OK:
                    SSL_CONNECT_ERROR_PREPARE_SEQUENCE(SSL_CONNECT_OK_ERROR_SEQUENCE_0);
                    NO_FAIL_TEST_POINT(TP_SSL_connect_0_OK, SSL_connect(SSL_Good_Ptr));
                    break;
                default:
                    SSL_CONNECT_ERROR_PREPARE_SEQUENCE(SSL_CONNECT_OK_ERROR_SEQUENCE_1);
                    NO_FAIL_TEST_POINT(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
                    NO_FAIL_TEST_POINT(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
                    NO_FAIL_TEST_POINT(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
                    break;
                }
            }

            // The Send tests for tlsio is in the Open state
            bool expect_ssl_write = false;
            switch (test_point)
            {
            case TP_SEND_NULL_BUFFER_FAIL:
            case TP_SEND_NULL_TLSIO_FAIL:
                // No expected call preparation needed here
                break;
            case TP_SSL_write_FAIL:
                expect_ssl_write = true;
                SSL_WRITE_ERROR_PREPARE_SEQUENCE(SSL_WRITE_FAIL_ERROR_SEQUENCE);
                break;
            case TP_SSL_write_OK:
                expect_ssl_write = true;
                SSL_WRITE_ERROR_PREPARE_SEQUENCE(SSL_WRITE_OK_ERROR_SEQUENCE);
                break;
            }
            if (expect_ssl_write)
            {
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_043: [ if the ssl was not able to send all data in the buffer, the tlsio_openssl_compact_send shall call the ssl again to send the remaining bytes. ]*/
                // The first SSL_write succeeds after a SSL_ERROR_WANT_READ and a SSL_ERROR_WANT_WRITE
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, SSL_send_buffer, 20));
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, SSL_send_buffer, 20));
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, SSL_send_buffer, 20));
                // The second SSL_write succeeds after a SSL_ERROR_WANT_READ and a SSL_ERROR_WANT_WRITE
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 8), 12));
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 8), 12));
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 8), 12));
                // The third SSL_write either succeeds or fails after a SSL_ERROR_WANT_READ and a SSL_ERROR_WANT_WRITE
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 16), 4));
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 16), 4));
                NO_FAIL_TEST_POINT(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 16), 4));
            }


            // Close SSL Connection Members
            /* Tests_SRS_SRS_TLSIO_OPENSSL_COMPACT_30_017: [ The tlsio_openssl_compact_destroy shall release tlsio_handle and all its associated resources. ]*/
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

            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_005: [ The tlsio_openssl_compact shall receive the connection information using the TLSIO_CONFIG structure defined in tlsio.h ]*/
            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_012: [ The tlsio_openssl_compact_create shall receive the connection configuration (TLSIO_CONFIG). ]*/
            TLSIO_CONFIG* cfg = test_point == TP_NULL_CONFIG_FAIL ? NULL : &tlsio_config;
            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_009: [ The tlsio_openssl_compact_create shall allocate, initialize, and return an instance of the tlsio for compact OpenSSL. ]*/
            CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(cfg);

            if (test_point <= TP_TLSIO_MALLOC_FAIL)
            {
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_010: [ If the allocation fails, tlsio_openssl_compact_create shall return NULL. ]*/
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_013: [ If the io_create_parameters value is NULL, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_015: [ If the IP for the hostName cannot be found, tlsio_openssl_compact_create shall return NULL. ]*/
                ASSERT_IS_NULL(tlsio);
            }

            if (tlsio)
            {
                // Handle options
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_052 [ The tlsio_openssl_compact_setoption shall do nothing and return 0. ]*/
                int set_option_result = tlsio_id->concrete_io_setoption(tlsio, NULL, NULL);
                ASSERT_ARE_EQUAL_WITH_MSG(int, 0, set_option_result, "Unexpected result from concrete_io_setoption");

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_053: [ The tlsio_openssl_compact_retrieveoptions shall do nothing and return NULL. ]*/
                OPTIONHANDLER_HANDLE retrieve_option_result = tlsio_id->concrete_io_retrieveoptions(tlsio);
                ASSERT_IS_NULL_WITH_MSG(retrieve_option_result, "Unexpected result from concrete_io_retrieveoptions");



                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // Open
                reset_callback_context_records();
                ACTIVATE_SSL_CONNECT_ERROR_SEQUENCE();
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_019: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_open shall do nothing except log an error and return FAILURE. ]*/
                CONCRETE_IO_HANDLE tlsio_for_open_call = test_point != TP_OPEN_NULL_TLSIO_FAIL ? tlsio : NULL;
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_020: [ If the on_bytes_received parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                ON_BYTES_RECEIVED on_bytes_received_for_open = test_point == TP_OPEN_NULL_BYTES_R_FAIL ? NULL : on_bytes_received;
                ON_IO_OPEN_COMPLETE open_callback = test_point != TP_Open_no_callback_OK ? on_io_open_complete : NULL;
                ASSERT_IO_OPEN_CALLBACK(false, 0);

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_021: [ The tlsio_openssl_compact_open shall open the ssl connection with the host provided in the tlsio_openssl_compact_create. ]*/
                int open_result = tlsio_id->concrete_io_open(tlsio_for_open_call, open_callback, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received_for_open,
                    IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);

                SSL_CONNECT_ERROR_ASSERT_LAST_ERROR_SEQUENCE();	// special checking for SSL_connect
                if (test_point >= TP_SSL_connect_0_OK)
                {
                    // Here the open succeeded
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_026: [ If tlsio_openssl_compact_open successfully opens the ssl connection, it shall return 0. ]*/
                    ASSERT_ARE_EQUAL_WITH_MSG(int, 0, open_result, "Unexpected concrete_io_open failure");
                    ASSERT_IO_ERROR_CALLBACK(false);
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_007: [ If the callback function is set as NULL. The tlsio_openssl_compact shall not call anything. ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_027: [ If tlsio_openssl_compact_open successfully opens the ssl connection and on_io_open_complete is non-NULL it shall call on_io_open_complete with IO_OPEN_OK. ]*/
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_028: [ If tlsio_openssl_compact_open calls on_io_open_complete, it shall always pass the provided on_io_open_complete_context parameter. ]*/
                    ASSERT_IO_OPEN_CALLBACK(test_point != TP_Open_no_callback_OK, IO_OPEN_OK);
                }
                else
                {
                    // Here the open failed
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_030: [ If tlsio_openssl_compact_open fails to open the ssl connection, it shall return FAILURE. ] */
                    ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, open_result, "Unexpected concrete_io_open success");
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_032: [ If the tlsio_openssl_compact_open fails to open the tls connection, and the on_io_error callback was provided, it shall call on_io_error and pass in the provided on_io_error_context. ]*/
                    bool expected_io_error_callback = test_point != TP_OPEN_NULL_TLSIO_FAIL ? true : false;
                    ASSERT_IO_ERROR_CALLBACK(expected_io_error_callback);
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_031: [ If the tlsio_openssl_compact_open fails to open the tls connection, and the on_io_open_complete callback was provided, it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
                    ASSERT_IO_OPEN_CALLBACK(true, IO_OPEN_ERROR);
                }

                // Open while still open
                if (test_point == TP_Open_while_still_open)
                {
                    reset_callback_context_records();
                    int open_second_result = tlsio_id->concrete_io_open(tlsio_for_open_call, open_callback, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received_for_open,
                        IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);
                    open_second_result;
                }

                // End Open
                /////////////////////////////////////////////////////////////////////////////////////////////////////


                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // Send
                if (test_point >= TP_SEND_NULL_BUFFER_FAIL && test_point <= TP_SSL_write_OK)
                {
                    ACTIVATE_SSL_WRITE_ERROR_SEQUENCE();
                    reset_callback_context_records();
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_046: [ If the buffer is NULL, the tlsio_openssl_compact_send shall do nothing except log the error and return FAILURE. ]*/
                    uint8_t* buffer = test_point == TP_SEND_NULL_BUFFER_FAIL ? NULL : SSL_send_buffer;
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_047: [ If the size is 0, the tlsio_openssl_compact_send shall do nothing and return 0. ]*/
                    size_t bytes_to_send = test_point == TP_Send_zero_bytes_OK ? 0 :20;	// 20 is 4 less than the buffer size
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_039: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_send shall do nothing except log an error and return FAILURE. ] ]*/
                    CONCRETE_IO_HANDLE tlsio_for_send_call = test_point == TP_SEND_NULL_TLSIO_FAIL ? 0 : tlsio;

                    int send_result = tlsio_id->concrete_io_send(tlsio_for_send_call, 
                        buffer, bytes_to_send, on_io_send_complete, IO_SEND_COMPLETE_CONTEXT);

                    if (test_point >= TP_SSL_write_OK)
                    {
                        // Successes here
                        ASSERT_ARE_EQUAL_WITH_MSG(int, 0, send_result, "Unexpected concrete_io_send failure");
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_003: [ The tlsio_openssl_compact shall report the send operation status using the IO_SEND_RESULT enumerator defined in the xio.h ]*/
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_007: [ If the callback function is set as NULL. The tlsio_openssl_compact shall not call anything. ]*/
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_041: [ The tlsio_openssl_compact_send shall call the provided on_send_complete callback function. ]*/
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_045: [ if the ssl was able to send all the bytes in the buffer, the tlsio_openssl_compact_send shall call the on_send_complete with IO_SEND_OK, and return 0 ]*/
                        ASSERT_IO_SEND_CALLBACK(test_point != TP_Send_no_callback_OK, IO_SEND_OK);
                    }
                    else
                    {
                        // Failures here
                        ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, send_result, "Unexpected concrete_io_send success");
                        bool expected_io_error_callback = 
                            (test_point == TP_SEND_NULL_TLSIO_FAIL || test_point == TP_SEND_NULL_BUFFER_FAIL) ? false : true;
                        ASSERT_IO_ERROR_CALLBACK(expected_io_error_callback);
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_003: [ The tlsio_openssl_compact shall report the send operation status using the IO_SEND_RESULT enumerator defined in the xio.h ]*/
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_041: [ The tlsio_openssl_compact_send shall call the provided on_send_complete callback function. ]*/
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_044: [ if the ssl fails before sending all of the bytes in the buffer, the tlsio_openssl_compact_send shall call the on_send_complete with IO_SEND_ERROR, and return FAILURE. ]*/
                        ASSERT_IO_SEND_CALLBACK(true, IO_SEND_ERROR);
                    }
                }
                // End send
                /////////////////////////////////////////////////////////////////////////////////////////////////////

                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // Close here
                bool close_already_called = false;
                switch (test_point)
                {
                case TP_SSL_write_FAIL:
                case TP_destroy_without_close_OK:
                case TP_Open_while_still_open:
                    close_already_called = true;
                    break;
                }

                if (test_point == TP_Close_NULL_TLSIO_FAIL)
                {
                    tlsio_id->concrete_io_close(NULL, NULL, NULL);
                }

                if (test_point == TP_Close_when_closed)
                {
                    tlsio_id->concrete_io_close(tlsio, NULL, NULL);
                }

                if (!close_already_called)
                {
                    ON_IO_CLOSE_COMPLETE close_callback = test_point != TP_Close_no_callback_OK ? on_io_close_complete : NULL;
                    if (open_result == 0)
                    {
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_035: [ The tlsio_openssl_compact_close return value shall be 0 except as noted in the next requirement. ] */
                        int close_return = tlsio_id->concrete_io_close(tlsio, close_callback, IO_CLOSE_COMPLETE_CONTEXT);
                        if (test_point == TP_Close_when_closed)
                        {
                            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_035: [ The tlsio_openssl_compact_close return value shall be 0 except as noted in the next requirement. ] */
                            ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, close_return, "Unexpected close success value");
                        }
                        else
                        {
                            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_036: [ If either tlsio_openssl_compact_close or tlsio_openssl_compact_create was called immediately prior to tlsio_openssl_compact_close, then tlsio_openssl_compact_close shall log an error and return FAILURE. ] */
                            ASSERT_ARE_EQUAL_WITH_MSG(int, 0, close_return, "Unexpected close fail return value");
                        }
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_037: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall call on_io_close_complete. ] */
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_038: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall pass the callback_context handle into the on_io_close_complete call. ] */
                        ASSERT_IO_CLOSE_CALLBACK(test_point != TP_Close_no_callback_OK);
                    }
                }
                // End close
                /////////////////////////////////////////////////////////////////////////////////////////////////////

                // Finally destroy
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
