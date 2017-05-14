// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#endif

/**
 * The gballoc.h will replace the malloc, free, and realloc by the my_gballoc functions, in this case,
 *    if you define these mock functions after include the gballoc.h, you will create an infinity recursion,
 *    so, places the my_gballoc functions before the #include "azure_c_shared_utility/gballoc.h"
 */
static void* my_gballoc_malloc(size_t size)
{
    return malloc(size);
}

static void* my_gballoc_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

static void my_gballoc_free(void* ptr)
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
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/dns_async.h"
#include "azure_c_shared_utility/socket_async.h"
#include "openssl/ssl.h"
#undef ENABLE_MOCKS

/**
 * Include the test tools.
 */
#include "testrunnerswitcher.h"
#include "umock_c.h"
#include "umocktypes_charptr.h"
#include "umocktypes_bool.h"
#include "umocktypes_stdint.h"
#include "umock_c_negative_tests.h"
#include "azure_c_shared_utility/macro_utils.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/xio.h"

// These "headers" are actuall source files that are broken out of this file for readability
#include "callbacks.h"
#include "ssl_errors.h"
#include "test_defines.h"

 /**
  * You can create some global variables that your test will need in some way.
  */
static TLSIO_CONFIG tlsio_config = { NULL, SSL_good_port_number, NULL, NULL };

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
        result = umocktypes_bool_register_types();
        ASSERT_ARE_EQUAL(int, 0, result);
        umocktypes_stdint_register_types();
        ASSERT_ARE_EQUAL(int, 0, result);

        /**
         * It is necessary to identify the types defined on your target. With it, the test system will 
         *    know how to use it. 
         *
         * On the target.h example, there is the type TARGET_HANDLE that is a void*
         */
        REGISTER_UMOCK_ALIAS_TYPE(SSL, void*);
        REGISTER_UMOCK_ALIAS_TYPE(SSL_CTX, void*);
        REGISTER_UMOCK_ALIAS_TYPE(SOCKET_ASYNC_OPTIONS_HANDLE, void*);
        REGISTER_UMOCK_ALIAS_TYPE(SOCKET_ASYNC_HANDLE, int);
        REGISTER_UMOCK_ALIAS_TYPE(DNS_ASYNC_HANDLE, void*);

        REGISTER_GLOBAL_MOCK_RETURNS(get_time, TIMEOUT_START_TIME, TIMEOUT_END_TIME_TIMEOUT);

        REGISTER_GLOBAL_MOCK_RETURNS(dns_async_create, GOOD_DNS_ASYNC_HANDLE, NULL);
        REGISTER_GLOBAL_MOCK_RETURNS(dns_async_is_lookup_complete, true, false);
        REGISTER_GLOBAL_MOCK_RETURNS(dns_async_get_ipv4, SSL_Get_IPv4_OK, SSL_Get_IPv4_FAIL);

        REGISTER_GLOBAL_MOCK_RETURNS(socket_async_create, SSL_Good_Socket, -1);

        REGISTER_GLOBAL_MOCK_RETURNS(SSL_new, SSL_Good_Ptr, NULL);
        REGISTER_GLOBAL_MOCK_RETURNS(SSL_CTX_new, SSL_Good_Context_Ptr, NULL);
        REGISTER_GLOBAL_MOCK_RETURNS(SSL_set_fd, 1, 0);
        REGISTER_GLOBAL_MOCK_RETURNS(SSL_connect, 0, SSL_ERROR);
        REGISTER_GLOBAL_MOCK_RETURNS(SSL_get_error, SSL_ERROR_WANT_READ, SSL_ERROR_HARD_FAIL);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_write, my_SSL_write);
        REGISTER_GLOBAL_MOCK_HOOK(SSL_read, my_SSL_read);

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
        tlsio_config.hostname = SSL_good_old_host_name;
    }

    /**
     * The test suite will call this function to cleanup your machine.
     * It is called only once, after all tests is done.
     */
    TEST_SUITE_CLEANUP(TestClassCleanup)
    {
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
    }

    /**
     * The test suite will call this function to cleanup your machine for the next test.
     * It is called after execute each test.
     */
    TEST_FUNCTION_CLEANUP(cleans)
    {
        TEST_MUTEX_RELEASE(g_testByTest);
    }

    TEST_FUNCTION(tlsio_openssl_compact__dowork_connection__succeeds)
    {
        ///arrange
        reset_callback_context_records();
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&good_config);
        int open_result = tlsio_id->concrete_io_open(tlsio, on_io_open_complete, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received,
            IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);
        ASSERT_ARE_EQUAL(int, open_result, 0);
        ASSERT_IO_OPEN_CALLBACK(false, IO_OPEN_ERROR);
        umock_c_reset_all_calls();

        // dowork_poll_dns (waiting)
        STRICT_EXPECTED_CALL(dns_async_is_lookup_complete(GOOD_DNS_ASYNC_HANDLE)).SetReturn(false);
        STRICT_EXPECTED_CALL(get_time(NULL));

        // dowork_poll_dns (done)
        STRICT_EXPECTED_CALL(dns_async_is_lookup_complete(GOOD_DNS_ASYNC_HANDLE));
        STRICT_EXPECTED_CALL(dns_async_get_ipv4(GOOD_DNS_ASYNC_HANDLE));
        STRICT_EXPECTED_CALL(dns_async_destroy(GOOD_DNS_ASYNC_HANDLE));
        STRICT_EXPECTED_CALL(socket_async_create(SSL_Get_IPv4_OK, SSL_good_port_number, false, NULL));

        // dowork_poll_socket (waiting)
        STRICT_EXPECTED_CALL(socket_async_is_create_complete(SSL_Good_Socket, IGNORED_PTR_ARG)).CopyOutArgumentBuffer_is_complete(&bool_false, sizeof_bool);
        STRICT_EXPECTED_CALL(get_time(NULL));

        // dowork_poll_socket (done)
        STRICT_EXPECTED_CALL(socket_async_is_create_complete(SSL_Good_Socket, IGNORED_PTR_ARG)).CopyOutArgumentBuffer_is_complete(&bool_true, sizeof_bool);
        STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_NUM_ARG));
        STRICT_EXPECTED_CALL(SSL_new(IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(SSL_set_fd(IGNORED_PTR_ARG, IGNORED_NUM_ARG));

        // dowork_poll_open_ssl (waiting SSL_ERROR_WANT_READ)
        STRICT_EXPECTED_CALL(SSL_connect(SSL_Good_Ptr)).SetReturn(SSL_ERROR);
        STRICT_EXPECTED_CALL(SSL_get_error(SSL_Good_Ptr, SSL_ERROR)).SetReturn(SSL_ERROR_WANT_READ);
        STRICT_EXPECTED_CALL(get_time(NULL));

        // dowork_poll_open_ssl (waiting SSL_ERROR_WANT_WRITE)
        STRICT_EXPECTED_CALL(SSL_connect(SSL_Good_Ptr)).SetReturn(SSL_ERROR);
        STRICT_EXPECTED_CALL(SSL_get_error(SSL_Good_Ptr, SSL_ERROR)).SetReturn(SSL_ERROR_WANT_WRITE);
        STRICT_EXPECTED_CALL(get_time(NULL));

        // dowork_poll_open_ssl (done)
        STRICT_EXPECTED_CALL(SSL_connect(SSL_Good_Ptr)).SetReturn(SSL_CONNECT_SUCCESS);

        ///act
        tlsio_id->concrete_io_dowork(tlsio); // dowork_poll_dns (waiting)
        tlsio_id->concrete_io_dowork(tlsio); // dowork_poll_dns (done)
        tlsio_id->concrete_io_dowork(tlsio); // dowork_poll_socket (waiting)
        tlsio_id->concrete_io_dowork(tlsio); // dowork_poll_socket (done)
        tlsio_id->concrete_io_dowork(tlsio); // dowork_poll_open_ssl (waiting SSL_ERROR_WANT_READ)
        tlsio_id->concrete_io_dowork(tlsio); // dowork_poll_open_ssl (waiting SSL_ERROR_WANT_WRITE)
        tlsio_id->concrete_io_dowork(tlsio); // dowork_poll_open_ssl (done)

        ///assert
        // Check that we go the on_open callback
        ASSERT_IO_OPEN_CALLBACK(true, IO_OPEN_OK);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        ///cleanup
        tlsio_id->concrete_io_close(tlsio, on_io_close_complete, NULL);
        tlsio_id->concrete_io_destroy(tlsio);
    }

    TEST_FUNCTION(tlsio_openssl_compact__dowork_pre_open__succeeds)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&good_config);
        umock_c_reset_all_calls();
        reset_callback_context_records();

        ///act
        tlsio_id->concrete_io_dowork(tlsio);

        ///assert
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_075: [ If tlsio_openssl_compact_dowork is called before tlsio_openssl_compact_open, tlsio_openssl_compact_dowork shall do nothing. ]*/
        ASSERT_NO_CALLBACKS();
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        ///cleanup
        tlsio_id->concrete_io_destroy(tlsio);
    }

    TEST_FUNCTION(tlsio_openssl_compact__dowork_parameter_validation__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

        ///act
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_070: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_dowork shall do nothing except log an error. ]*/
        tlsio_id->concrete_io_dowork(NULL);

        ///assert
        ASSERT_NO_CALLBACKS();

        ///cleanup
    }

    TEST_FUNCTION(tlsio_openssl_compact__open__succeeds)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&good_config);
        umock_c_reset_all_calls();
        reset_callback_context_records();

        STRICT_EXPECTED_CALL(get_time(NULL));
        STRICT_EXPECTED_CALL(dns_async_create(IGNORED_PTR_ARG, NULL));

        ///act
        int open_result = tlsio_id->concrete_io_open(tlsio, on_io_open_complete, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received,
            IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);

        ///assert
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_036: [ If tlsio_openssl_compact_open successfully begins opening the OpenSSL connection, it shall return 0. ]*/
        ASSERT_ARE_EQUAL(int, open_result, 0);
        // Should not have made any callbacks yet
        ASSERT_IO_OPEN_CALLBACK(false, IO_OPEN_ERROR);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        ///cleanup
        tlsio_id->concrete_io_destroy(tlsio);
    }

    TEST_FUNCTION(tlsio_openssl_compact__open_unhappy_paths__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&good_config);
        reset_callback_context_records();

        ///act
        int open_result = tlsio_id->concrete_io_open(tlsio, on_io_open_complete, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received,
            IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);
        int open_result_2 = tlsio_id->concrete_io_open(tlsio, on_io_open_complete, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received,
            IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);

        ///assert
        ASSERT_ARE_EQUAL(int, open_result, 0);
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_037: [ If tlsio_openssl_compact_open has already been called, it shall log an error, and return FAILURE. ]*/
        ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, open_result_2, 0, "Unexpected 2nd open success");
        ASSERT_IO_OPEN_CALLBACK(true, IO_OPEN_ERROR);

        ///cleanup
        tlsio_id->concrete_io_destroy(tlsio);
    }

    TEST_FUNCTION(tlsio_openssl_compact__open_parameter_validation_fails__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

        // Parameters arrays
        bool p0[OPEN_PV_COUNT];
        ON_IO_OPEN_COMPLETE p1[OPEN_PV_COUNT];
        ON_BYTES_RECEIVED p2[OPEN_PV_COUNT];
        ON_IO_ERROR p3[OPEN_PV_COUNT];
        const char* fm[OPEN_PV_COUNT];

        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_030: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_031: [ If the on_io_open_complete parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_032: [ If the on_bytes_received parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_033: [ If the on_io_error parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
        int k = 0;
        p0[k] = false; p1[k] = on_io_open_complete; p2[k] = on_bytes_received; p3[k] = on_io_error; fm[k] = "Unexpected open success when tlsio_handle is NULL"; /* */  k++;
        p0[k] = true; p1[k] = NULL; /*           */ p2[k] = on_bytes_received; p3[k] = on_io_error; fm[k] = "Unexpected open success when on_io_open_complete is NULL"; k++;
        p0[k] = true; p1[k] = on_io_open_complete; p2[k] = NULL; /*         */ p3[k] = on_io_error; fm[k] = "Unexpected open success when on_bytes_received is NULL"; k++;
        p0[k] = true; p1[k] = on_io_open_complete; p2[k] = on_bytes_received;  p3[k] = NULL; /*  */ fm[k] = "Unexpected open success when on_io_error is NULL"; /*   */ k++;

        // Cycle through each failing combo of parameters
        for (int i = 0; i < OPEN_PV_COUNT; i++)
        {
            ///arrange
            reset_callback_context_records();
            CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&good_config);

            ///act
            int open_result = tlsio_id->concrete_io_open(p0[i] ? tlsio : NULL, p1[i], IO_OPEN_COMPLETE_CONTEXT, p2[i],
                IO_BYTES_RECEIVED_CONTEXT, p3[i], IO_ERROR_CONTEXT);

            ///assert
            ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, open_result, 0, fm[i]);
            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_039: [If the tlsio_openssl_compact_open returns FAILURE it shall call on_io_open_complete with the provided on_io_open_complete_context and IO_OPEN_ERROR.]*/
            ASSERT_IO_OPEN_CALLBACK(p1[i] != NULL, IO_OPEN_ERROR);

            ///cleanup
            tlsio_id->concrete_io_destroy(tlsio);
        }
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_123 [ The tlsio_openssl_compact_setoption shall do nothing and return 0. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__setoption__succeeds)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&good_config);
        ASSERT_IS_NOT_NULL(tlsio);
        umock_c_reset_all_calls();

        ///act
        int result = tlsio_id->concrete_io_setoption(tlsio, "fake name", "fake value");

        ///assert
        ASSERT_ARE_EQUAL(int, 0, result);

        ///cleanup
        tlsio_id->concrete_io_destroy(tlsio);
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_120: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_121: [ If the optionName parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_122: [ If the value parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__setoption_parameter_validation__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        umock_c_reset_all_calls();

        // Parameters arrays
        bool p0[SETOPTION_PV_COUNT];
        const char* p1[SETOPTION_PV_COUNT];
        const char*  p2[SETOPTION_PV_COUNT];
        const char* fm[SETOPTION_PV_COUNT];

        int k = 0;
        p0[k] = false; p1[k] = "fake name"; p2[k] = "fake value"; fm[k] = "Unexpected setoption success when tlsio_handle is NULL"; /* */  k++;
        p0[k] = true; p1[k] = NULL; /*   */ p2[k] = "fake value"; fm[k] = "Unexpected setoption success when option_name is NULL"; /*  */  k++;
        p0[k] = true; p1[k] = "fake name"; p2[k] = NULL; /*    */ fm[k] = "Unexpected setoption success when option_value is NULL"; /* */  k++;


        // Cycle through each failing combo of parameters
        for (int i = 0; i < SETOPTION_PV_COUNT; i++)
        {
            ///arrange
            CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&good_config);
            ASSERT_IS_NOT_NULL(tlsio);
            ///act

            int result = tlsio_id->concrete_io_setoption(p0[i] ? tlsio : NULL, p1[i], p2[i]);

            ///assert
            ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, result, fm[i]);

            ///cleanup
            tlsio_id->concrete_io_destroy(tlsio);
        }
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_160: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_retrieveoptions shall do nothing except log an error and return FAILURE. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__retrieveoptions_parameter_validation__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

        ///act
        OPTIONHANDLER_HANDLE result = tlsio_id->concrete_io_retrieveoptions(NULL);

        ///assert
        ASSERT_IS_NULL((void*)result);

        ///cleanup
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_161: [ The tlsio_openssl_compact_retrieveoptions shall do nothing and return NULL. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__retrieveoptions__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&good_config);
        ASSERT_IS_NOT_NULL(tlsio);
        umock_c_reset_all_calls();

        ///act
        OPTIONHANDLER_HANDLE result = tlsio_id->concrete_io_retrieveoptions(tlsio);

        ///assert
        ASSERT_IS_NULL((void*)result);

        ///cleanup
        tlsio_id->concrete_io_destroy(tlsio);
    }

    TEST_FUNCTION(tlsio_openssl_compact__create_parameter_validation_fails__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        TLSIO_CONFIG config[4];
        create_parameters_t p[4];
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_013: [ If the io_create_parameters value is NULL, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_014: [ If the hostname member of io_create_parameters value is NULL, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_015: [ If the port member of io_create_parameters value is less than 0 or greater than 0xffff, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
        //                               config       hostname            port number                failure message
        populate_create_parameters(p + 0, NULL, /* */ SSL_good_host_name, SSL_good_port_number, "Should fail with NULL config");
        populate_create_parameters(p + 1, config + 1, NULL, /*         */ SSL_good_port_number, "Should fail with NULL hostname");
        populate_create_parameters(p + 2, config + 2, SSL_good_host_name, SSL_port_number_too_low, "Should fail with port number too low");
        populate_create_parameters(p + 3, config + 3, SSL_good_host_name, SSL_port_number_too_high, "Should fail with port number too high");

        // Cycle through each failing combo of parameters
        for (int i = 0; i < sizeof(config) / sizeof(TLSIO_CONFIG); i++)
        {
            ///act
            CONCRETE_IO_HANDLE result = tlsio_id->concrete_io_create(p[i].config);

            ///assert
            ASSERT_IS_NULL_WITH_MSG(result, p[i].fail_msg);
        }
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_011: [ If any resource allocation fails, tlsio_openssl_compact_create shall return NULL. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__create_unhappy_paths__fails)
    {
        ///arrange
        int negativeTestsInitResult = umock_c_negative_tests_init();
        ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // concrete_io struct
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // copy hostname
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // singlylinkedlist_create
        umock_c_negative_tests_snapshot();

        for (unsigned int i = 0; i < umock_c_negative_tests_call_count(); i++)
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(i);

            ///act
            CONCRETE_IO_HANDLE result = tlsio_id->concrete_io_create(&good_config);

            ///assert
            ASSERT_IS_NULL(result);
        }

        ///cleanup
        umock_c_negative_tests_deinit();
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_010: [ The tlsio_openssl_compact_create shall allocate and initialize all necessary resources and return an instance of the tlsio_openssl_compact. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__create__succeeds)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // concrete_io struct
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_016: [ tlsio_openssl_compact_create shall make a copy of the hostname member of io_create_parameters to allow deletion of hostname immediately after the call. ]*/
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // copy hostname
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // singlylinkedlist_create
        //

        ///act
        CONCRETE_IO_HANDLE result = tlsio_id->concrete_io_create(&good_config);

        ///assert
        ASSERT_IS_NOT_NULL(result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        ///cleanup
        tlsio_id->concrete_io_destroy(result);
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_020: [ If tlsio_handle is NULL, tlsio_openssl_compact_destroy shall do nothing. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__destroy_parameter_validation__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

        ///act
        tlsio_id->concrete_io_destroy(NULL);

        ///assert
        // can't really check anything here

        ///cleanup
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_021: [ The tlsio_openssl_compact_destroy shall release all allocated resources and then release tlsio_handle. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__destroy_unopened__succeeds)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        CONCRETE_IO_HANDLE result = tlsio_id->concrete_io_create(&good_config);
        ASSERT_IS_NOT_NULL(result);
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_NUM_ARG));  // copy hostname
        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_NUM_ARG));  // singlylinkedlist_create
        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_NUM_ARG));  // concrete_io struct
        //

        ///act
        tlsio_id->concrete_io_destroy(result);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        ///cleanup
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
    TEST_FUNCTION(tlsio_openssl_compact__tlsio_get_interface_description)
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
