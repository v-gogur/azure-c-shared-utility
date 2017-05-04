// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#ifdef WIN32
// The timeout unit tests take 20 seconds each, so they're only run manually in Windows
//#define UNIT_TEST_RUN_TIMEOUT_TESTS
#endif
#define SSL_MAX_BLOCK_TIME_SECONDS 20

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

// These "headers" are actuall source files that are broken out of this file for readability
#include "callbacks.h"
#include "ssl_errors.h"
#include "test_points.h"
#include "tlsio_internals.h"

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
        tlsio_config.hostname = SSL_goood_host_name;
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

    // This main_sequence test performs all of the test passes that require sequencing of tlsio calls
    // To do this, it expands on the mocking framework's negative tests concept by adding
    // "test point", which are defined in the test_points.h file. These test points capture the 
    // process of testing the tlsio, and reading the test_points.h file first will make the following
    // function make a lot more sense.
    TEST_FUNCTION(tlsio_openssl_main_sequence)
    {

        for (int test_point = 0; test_point <= TP_FINAL_OK; test_point++)
        {
#ifndef UNIT_TEST_RUN_TIMEOUT_TESTS
            if (test_point == TP_SSL_connect_TIMEOUT_FAIL || test_point == TP_SSL_write_TIMEOUT_FAIL)
            {
                printf("\n\nSkipping timeout test point: %d  %s\n", test_point, test_point_names[test_point].name);
                continue;
            }
#endif
            /////////////////////////////////////////////////////////////////////////////
            ///arrange
            /////////////////////////////////////////////////////////////////////////////
            umock_c_reset_all_calls();

            InitTestPoints();

            int negativeTestsInitResult = umock_c_negative_tests_init();
            ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);


            // The Create test points
            //      TP_NULL_CONFIG_FAIL
            //      TP_DNS_FAIL
            //      TP_TLSIO_MALLOC_FAIL
            //
            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_015:  [ If the IP for the hostName cannot be found, tlsio_openssl_compact_dowork shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
            TEST_POINT(TP_DNS_FAIL, SSL_Get_IPv4(SSL_goood_host_name));
            TEST_POINT(TP_TLSIO_MALLOC_FAIL, gballoc_malloc(IGNORED_NUM_ARG));

            // Handle options


            // The Open test points
            //      TP_OPEN_NULL_TLSIO_FAIL
            //      TP_OPEN_NULL_BYTES_R_FAIL
            //      TP_OPEN_NULL_ON_ERROR_FAIL
            //      TP_SOCKET_OPEN_FAIL
            //      TP_SSL_CTX_new_FAIL
            //      TP_SSL_new_FAIL
            //      TP_SSL_set_fd_FAIL
            //      TP_SSL_connect_TIMEOUT_FAIL
            //      TP_SSL_connect_0_FAIL
            //      TP_SSL_connect_1_FAIL
            //      TP_SSL_connect_0_OK
            //      TP_SSL_connect_1_OK
            //      TP_Open_no_callback_OK
            //      TP_Open_while_still_open_FAIL
            //
            TEST_POINT(TP_SOCKET_OPEN_FAIL, SSL_Socket_Create(SSL_Get_IPv4_OK, SSL_goood_port_number));
            TEST_POINT(TP_SSL_CTX_new_FAIL, SSL_CTX_new(IGNORED_NUM_ARG));
            TEST_POINT(TP_SSL_new_FAIL, SSL_new(SSL_Good_Context_Ptr));
            TEST_POINT(TP_SSL_set_fd_FAIL, SSL_set_fd(SSL_Good_Ptr, SSL_Good_Socket));

            // SSL_connect can succeed and fail in several different sequences
            if (test_point < TP_SSL_connect_TIMEOUT_FAIL)
            {
                PREPARE_ERROR_SEQUENCE_FOR_UNCALLED_SSL_CONNECT();
            }
            else
            {
                switch (test_point)
                {
                case TP_SSL_connect_TIMEOUT_FAIL:
                    PREPARE_ERROR_SEQUENCE_FOR_SSL_CONNECT_TIMEOUT();
                    break;
                case TP_SSL_connect_0_FAIL:
                    PREPARE_ERROR_SEQUENCE_FOR_SSL_CONNECT(SSL_CONNECT_FAIL_ERROR_SEQUENCE_0);
                    TEST_POINT_NO_FAIL(TP_SSL_connect_0_FAIL, SSL_connect(SSL_Good_Ptr));
                    break;
                case TP_SSL_connect_1_FAIL:
                    PREPARE_ERROR_SEQUENCE_FOR_SSL_CONNECT(SSL_CONNECT_FAIL_ERROR_SEQUENCE_1);
                    TEST_POINT_NO_FAIL(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
                    TEST_POINT_NO_FAIL(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
                    TEST_POINT_NO_FAIL(TP_SSL_connect_1_FAIL, SSL_connect(SSL_Good_Ptr));
                    break;
                case TP_SSL_connect_0_OK:
                    PREPARE_ERROR_SEQUENCE_FOR_SSL_CONNECT(SSL_CONNECT_OK_ERROR_SEQUENCE_0);
                    TEST_POINT_NO_FAIL(TP_SSL_connect_0_OK, SSL_connect(SSL_Good_Ptr));
                    break;
                default:
                    PREPARE_ERROR_SEQUENCE_FOR_SSL_CONNECT(SSL_CONNECT_OK_ERROR_SEQUENCE_1);
                    TEST_POINT_NO_FAIL(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
                    TEST_POINT_NO_FAIL(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
                    TEST_POINT_NO_FAIL(TP_SSL_connect_1_OK, SSL_connect(SSL_Good_Ptr));
                    break;
                }
            }

            // At this point all of the failed open calls have been done, and our adapter is now 
            // properly opened

            // The Send test points
            //      TP_SEND_NULL_BUFFER_FAIL
            //      TP_SEND_NULL_TLSIO_FAIL
            //      TP_SSL_write_TIMEOUT_FAIL
            //      TP_SSL_write_FAIL
            //      TP_SSL_write_OK
            //      TP_Send_no_callback_OK
            //      TP_Send_zero_bytes_OK
            //
            bool expect_ssl_write = false;
            switch (test_point)
            {
                case TP_SEND_NULL_BUFFER_FAIL:
                case TP_SEND_NULL_TLSIO_FAIL:
                case TP_Send_zero_bytes_OK:
                    // No expected call preparation needed here
                    break;
                case TP_SSL_write_TIMEOUT_FAIL:
                    PREPARE_ERROR_SEQUENCE_FOR_SSL_WRITE_TIMEOUT();
                    expect_ssl_write = false;
                    break;
                case TP_SSL_write_FAIL:
                    expect_ssl_write = true;
                    PREPARE_ERROR_SEQUENCE_FOR_SSL_WRITE(SSL_WRITE_FAIL_ERROR_SEQUENCE);
                    break;
                case TP_SSL_write_OK:
                case TP_Send_no_callback_OK:
                    expect_ssl_write = true;
                    PREPARE_ERROR_SEQUENCE_FOR_SSL_WRITE(SSL_WRITE_OK_ERROR_SEQUENCE);
                    break;
            }
            if (expect_ssl_write)
            {
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_043: [ if the ssl send was not able to send an entire enqueued message at once, tlsio_openssl_compact_dowork shall call the ssl again to send the remaining bytes. ]*/
                // The first SSL_write succeeds after a SSL_ERROR_WANT_READ and a SSL_ERROR_WANT_WRITE
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, SSL_send_buffer, 20));
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, SSL_send_buffer, 20));
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, SSL_send_buffer, 20));
                // The second SSL_write succeeds after a SSL_ERROR_WANT_READ and a SSL_ERROR_WANT_WRITE
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 8), 12));
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 8), 12));
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 8), 12));
                // The third SSL_write either succeeds or fails after a SSL_ERROR_WANT_READ and a SSL_ERROR_WANT_WRITE
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 16), 4));
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 16), 4));
                TEST_POINT_NO_FAIL(TP_SSL_write_FAIL, SSL_write(SSL_Good_Ptr, (SSL_send_buffer + 16), 4));
            }

            // The DoWork test points
            //      TP_SSL_read_NULL_TLSIO_FAIL
            //      TP_SSL_read_OK
            //
            switch (test_point)
            {
                case TP_SSL_read_NULL_TLSIO_FAIL:
                    TEST_POINT_NO_FAIL(TP_SSL_read_OK, SSL_read(NULL, IGNORED_PTR_ARG, IGNORED_NUM_ARG));
                    break;
                case TP_SSL_read_OK:
                    TEST_POINT_NO_FAIL(TP_SSL_read_OK, SSL_read(SSL_Good_Ptr, IGNORED_PTR_ARG, IGNORED_NUM_ARG));
                    break;
            }



            // The Close test points
            //      TP_Close_NULL_TLSIO_FAIL
            //      TP_Close_no_callback_OK
            //      TP_Close_when_closed_OK
            //
            // Close SSL Connection Members
            /* Tests_SRS_SRS_TLSIO_OPENSSL_COMPACT_30_017:  [ The tlsio_openssl_compact_destroy shall release all allocated resources and then release tlsio_handle. ]*/
            TEAR_DOWN_POINT(TP_SSL_connect_1_FAIL, SSL_shutdown(SSL_Good_Ptr));
            TEAR_DOWN_POINT(TP_SSL_new_FAIL, SSL_free(SSL_Good_Ptr));
            TEAR_DOWN_POINT(TP_SSL_CTX_new_FAIL, SSL_CTX_free(SSL_Good_Context_Ptr));
            TEAR_DOWN_POINT(TP_SOCKET_OPEN_FAIL, SSL_Socket_Close(SSL_Good_Socket));


            // The Destroy test points
            //      TP_Destroy_NULL_TLSIO_FAIL
            //      TP_Destroy_without_close_OK
            //      TP_FINAL_OK
            //
            TEAR_DOWN_POINT(TP_TLSIO_MALLOC_FAIL, gballoc_free(IGNORED_PTR_ARG));      //This is the free of TLS_IO_INSTANCE.


            umock_c_negative_tests_snapshot();

            umock_c_negative_tests_reset();

            // Each test pass has no more than one place where umock_c_negative_tests_fail_call 
            // will force a failure.   
            uint16_t fail_index = test_points[test_point];
            if (fail_index != 0xffff)
            {
                umock_c_negative_tests_fail_call(fail_index);
            }

            // Show the test point description in the output for the sake of 
            // human readability
            test_point_label_output(test_point);

            //////////////////////////////////////////////////////////////////////////////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////////////////////////
            ///act
            //////////////////////////////////////////////////////////////////////////////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////////////////////////

            const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

            /////////////////////////////////////////////////////////////////////////////////////////////////////
            // The Create test points
            //      TP_NULL_CONFIG_FAIL
            //      TP_DNS_FAIL
            //      TP_TLSIO_MALLOC_FAIL
            //
            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_005: [ The tlsio_openssl_compact shall receive the connection information using the TLSIO_CONFIG structure defined in tlsio.h ]*/
            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_012: [ The tlsio_openssl_compact_create shall receive the connection configuration (TLSIO_CONFIG). ]*/
            TLSIO_CONFIG* cfg = test_point == TP_NULL_CONFIG_FAIL ? NULL : &tlsio_config;

            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_009: [ The tlsio_openssl_compact_create shall allocate and initialize all necessary resources and return an instance of the tlsio_openssl_compact. ]*/
            CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(cfg);

            switch (test_point)
            {
                case TP_NULL_CONFIG_FAIL:
                case TP_DNS_FAIL:
                case TP_TLSIO_MALLOC_FAIL:
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_010: [ If the allocation fails, tlsio_openssl_compact_create shall return NULL. ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_013: [ If the io_create_parameters value is NULL, tlsio_openssl_compact_create shall log an error and return NULL. ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_015:  [ If the IP for the hostName cannot be found, tlsio_openssl_compact_dowork shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
                    ASSERT_IS_NULL(tlsio);
                    break;
                default:
                    // All other test points need the create to succeed
                    ASSERT_IS_NOT_NULL(tlsio);
                    break;
            }
            // end Create
            /////////////////////////////////////////////////////////////////////////////////////////////////////

            if (tlsio)
            {
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_009: [ The tlsio_openssl_compact_create shall allocate and initialize all necessary resources and return an instance of the tlsio_openssl_compact. ]*/
                ASSERT_TLSIO_NEWLY_CREATED(tlsio);
                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // The Set Option test points
                //      TP_SET_OPTION_NULL_TLSIO_FAIL
                //      TP_SET_OPTION_NULL_OPT_NAME_FAIL
                //      TP_SET_OPTION_NULL_OPT_VALUE_FAIL
                //
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_053: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
                CONCRETE_IO_HANDLE tlsio_for_set_option = test_point == TP_SET_OPTION_NULL_TLSIO_FAIL ? NULL : tlsio;

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_054: [ If the optionName parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
                const char* option_name_for_set_option = test_point == TP_SET_OPTION_NULL_OPT_NAME_FAIL ? NULL : "test name";

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_055: [ If the value parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
                const char* option_value_for_set_option = test_point == TP_SET_OPTION_NULL_OPT_VALUE_FAIL ? NULL : "test value";

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_056 [ The tlsio_openssl_compact_setoption shall do nothing and return 0. ]*/
                int set_option_result = tlsio_id->concrete_io_setoption(tlsio_for_set_option, option_name_for_set_option, option_value_for_set_option);
                if (test_point <= TP_SET_OPTION_NULL_OPT_VALUE_FAIL)
                {
                    //ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, set_option_result, "Unexpected failure from concrete_io_setoption");
                    set_option_result;
                    // Options are not fully supported yet
                }
                else
                {
                    //ASSERT_ARE_EQUAL_WITH_MSG(int, 0, set_option_result, "Unexpected success from concrete_io_setoption");
                    // Options are not fully supported yet
                }

                // end Set Options
                /////////////////////////////////////////////////////////////////////////////////////////////////////

                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // The Retrieve Options test points
                //      TP_GET_OPTION_NULL_TLSIO_FAIL
                //
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_057: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_retrieveoptions shall do nothing except log an error and return NULL. ]*/
                CONCRETE_IO_HANDLE tlsio_for_retrieve_options = test_point == TP_GET_OPTION_NULL_TLSIO_FAIL ? NULL : tlsio;

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_058: [ The tlsio_openssl_compact_retrieveoptions shall do nothing and return NULL. ]*/
                OPTIONHANDLER_HANDLE retrieve_option_result = tlsio_id->concrete_io_retrieveoptions(tlsio_for_retrieve_options);
                ASSERT_IS_NULL_WITH_MSG(retrieve_option_result, "Unexpected result from concrete_io_retrieveoptions");
                // end options
                /////////////////////////////////////////////////////////////////////////////////////////////////////


                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // The Open test points
                //      TP_OPEN_NULL_TLSIO_FAIL
                //      TP_OPEN_NULL_BYTES_R_FAIL
                //      TP_OPEN_NULL_ON_ERROR_FAIL
                //      TP_SOCKET_OPEN_FAIL
                //      TP_SSL_CTX_new_FAIL
                //      TP_SSL_new_FAIL
                //      TP_SSL_set_fd_FAIL
                //      TP_SSL_connect_TIMEOUT_FAIL
                //      TP_SSL_connect_0_FAIL
                //      TP_SSL_connect_1_FAIL
                //      TP_SSL_connect_0_OK
                //      TP_SSL_connect_1_OK
                //      TP_Open_no_callback_OK
                //      TP_Open_while_still_open_FAIL
                //
                reset_callback_context_records();
                ACTIVATE_SSL_CONNECT_ERROR_SEQUENCE();
                time_t open_start_time = time(NULL);

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_019: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                CONCRETE_IO_HANDLE tlsio_for_open_call = test_point == TP_OPEN_NULL_TLSIO_FAIL ?NULL : tlsio;

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_020: [ If the on_bytes_received parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                ON_BYTES_RECEIVED on_bytes_received_for_open = test_point == TP_OPEN_NULL_BYTES_R_FAIL ? NULL : on_bytes_received;

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_052: [ If the on_io_error parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                ON_IO_ERROR on_io_error_for_open = test_point == TP_OPEN_NULL_ON_ERROR_FAIL ? NULL : on_io_error;

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_007: [ If the callback function is set as NULL, the tlsio_openssl_compact shall not call anything. ]*/
                ON_IO_OPEN_COMPLETE open_callback = test_point == TP_Open_no_callback_OK ?  NULL : on_io_open_complete;

                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_021: [ The tlsio_openssl_compact_open shall begin the process of opening the ssl connection with the host provided in the tlsio_openssl_compact_create call. ]*/
                int open_result = tlsio_id->concrete_io_open(tlsio_for_open_call, open_callback, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received_for_open,
                    IO_BYTES_RECEIVED_CONTEXT, on_io_error_for_open, IO_ERROR_CONTEXT);

                ASSERT_SSL_CONNECT_ERROR_SEQUENCE();	// special checking for SSL_connect
                ASSERT_IO_ERROR_CALLBACK(false);
                if (test_point >= TP_SSL_connect_0_OK)
                {
                    // Here the open succeeded
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_026: [ If tlsio_openssl_compact_open successfully begins opening the ssl connection, it shall return 0. ]*/
                    ASSERT_TLSIO_OPEN(tlsio);
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_019: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_open log an error and return FAILURE. ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_020: [ If the on_bytes_received parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_052: [ If the on_io_error parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                    ASSERT_ARE_EQUAL_WITH_MSG(int, 0, open_result, "Unexpected concrete_io_open failure return");

                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_007: [ If the callback function is set as NULL, the tlsio_openssl_compact shall not call anything. ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_027:  [ If tlsio_openssl_compact_dowork successfully opens the ssl connection it shall call on_io_open_complete with IO_OPEN_OK. ]*/
                    /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_028: [ If tlsio_openssl_compact_open calls on_io_open_complete, it shall always pass the provided on_io_open_complete_context parameter. ]*/
                    ASSERT_IO_OPEN_CALLBACK(test_point != TP_Open_no_callback_OK, IO_OPEN_OK);
                }
                else
                {
                    // Here the open failed
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_030: [ If tlsio_openssl_compact_dowork fails to open the ssl connection it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
                    ASSERT_TLSIO_NOT_OPEN(tlsio);
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_020: [ If the on_bytes_received parameter is NULL, tlsio_openssl_compact_open shall log an error and return FAILURE. ]*/
                    ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, open_result, "Unexpected concrete_io_open success return");

                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_002: [ The tlsio_openssl_compact shall report the open operation status using the IO_OPEN_RESULT enumerator defined in the xio.h ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_031: [ If the tlsio_openssl_compact_open returns FAILURE it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
                    ASSERT_IO_OPEN_CALLBACK(true, IO_OPEN_ERROR);

                    if (test_point == TP_SSL_connect_TIMEOUT_FAIL)
                    {
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_074: [ The tlsio_openssl_compact_send shall spend no longer than the internally defined SSL_MAX_BLOCK_TIME_SECONDS (20 seconds) attempting to perform the SSL_connect operation. ]*/
                        time_t elapsed = time(NULL) - open_start_time;
                        printf("TP_SSL_connect_TIMEOUT_FAIL time expected approx %u seconds, is %u seconds\n", SSL_MAX_BLOCK_TIME_SECONDS, (unsigned int)elapsed);
                        if (elapsed < SSL_MAX_BLOCK_TIME_SECONDS || elapsed > SSL_MAX_BLOCK_TIME_SECONDS + 2)
                        {
                            ASSERT_FAIL("Unexpected timeout elapsed time");
                        }
                    }
                }

                // Open while still open
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_029: [ If tlsio_openssl_compact_open has already been called, it shall log an error, and return FAILURE. ]*/
                /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_031: [ If the tlsio_openssl_compact_open returns FAILURE it shall call on_io_open_complete with IO_OPEN_ERROR. ]*/
                if (test_point == TP_Open_while_still_open_FAIL)
                {
                    reset_callback_context_records();
                    int open_second_result = tlsio_id->concrete_io_open(tlsio_for_open_call, open_callback, IO_OPEN_COMPLETE_CONTEXT, on_bytes_received_for_open,
                        IO_BYTES_RECEIVED_CONTEXT, on_io_error, IO_ERROR_CONTEXT);
                    ASSERT_TLSIO_OPEN(tlsio);
                    ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, open_second_result, "Redundant open call should fail");
                    ASSERT_IO_OPEN_CALLBACK(true, IO_OPEN_ERROR);
                }

                // End Open
                /////////////////////////////////////////////////////////////////////////////////////////////////////


                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // The Send test points
                //      TP_SEND_NULL_BUFFER_FAIL
                //      TP_SEND_NULL_TLSIO_FAIL
                //      TP_SSL_write_TIMEOUT_FAIL
                //      TP_SSL_write_FAIL
                //      TP_SSL_write_OK
                //      TP_Send_no_callback_OK
                //      TP_Send_zero_bytes_OK
                //
                if (test_point >= TP_SEND_NULL_BUFFER_FAIL && test_point <= TP_Send_zero_bytes_OK)
                {
                    ACTIVATE_SSL_WRITE_ERROR_SEQUENCE();
                    reset_callback_context_records();
                    time_t send_start_time = time(NULL);


                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_046: [ If the buffer is NULL, the tlsio_openssl_compact_send shall log the error and return FAILURE. ]*/
                    uint8_t* buffer = test_point == TP_SEND_NULL_BUFFER_FAIL ? NULL : SSL_send_buffer;

                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_047: [ If an enqueued message size is 0, the tlsio_openssl_compact_dowork shall just call the on_send_complete with IO_SEND_OK. ]*/
                    size_t bytes_to_send = test_point == TP_Send_zero_bytes_OK ? 0 :20;	// 20 is 4 less than the buffer size

                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_039: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_send shall log an error and return FAILURE. ] ]*/
                    CONCRETE_IO_HANDLE tlsio_for_send_call = test_point == TP_SEND_NULL_TLSIO_FAIL ? 0 : tlsio;

                    int send_result = tlsio_id->concrete_io_send(tlsio_for_send_call, 
                        buffer, bytes_to_send, on_io_send_complete, IO_SEND_COMPLETE_CONTEXT);

                    if (test_point == TP_SSL_write_FAIL || test_point == TP_SSL_write_TIMEOUT_FAIL)
                    {
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_044: [ If the ssl fails before sending all of the bytes in an enqueued message, the tlsio_openssl_compact_dowork shall call the on_send_complete with IO_SEND_ERROR. ]*/
                        /* Codes_SRS_TLSIO_OPENSSL_COMPACT_30_070: [ if the supplied message cannot be enqueued for transmission, tlsio_openssl_compact_send shall call the on_send_complete with IO_SEND_ERROR, and return FAILURE. ]*/
                        ASSERT_TLSIO_NOT_OPEN(tlsio);
                    }
                    else
                    {
                        // Only TP_SSL_write_FAIL and TP_SSL_write_TIMEOUT_FAIL should force a close
                        ASSERT_TLSIO_OPEN(tlsio);
                    }

                    ASSERT_SSL_WRITE_ERROR_SEQUENCE();	// special checking for SSL_write
                    if (test_point >= TP_SSL_write_OK)
                    {
                        // Successes here
                        ASSERT_ARE_EQUAL_WITH_MSG(int, 0, send_result, "Unexpected concrete_io_send failure");

                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_003: [ The tlsio_openssl_compact shall report the send operation status using the IO_SEND_RESULT enumerator defined in the xio.h ]*/
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_007: [ If the callback function is set as NULL, the tlsio_openssl_compact shall not call anything. ]*/
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_045: [ If the ssl was able to send all the bytes in an enqueued message, the tlsio_openssl_compact_dowork shall call the on_send_complete with IO_SEND_OK. ]*/
                        ASSERT_IO_SEND_CALLBACK(test_point != TP_Send_no_callback_OK, IO_SEND_OK);
                    }
                    else
                    {
                        // Failures here
                        bool expected_io_error_callback = 
                            (test_point == TP_SEND_NULL_TLSIO_FAIL || test_point == TP_SEND_NULL_BUFFER_FAIL) ? false : true;
                        ASSERT_IO_ERROR_CALLBACK(expected_io_error_callback);

                        ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, send_result, "Unexpected concrete_io_send success");

                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_003: [ The tlsio_openssl_compact shall report the send operation status using the IO_SEND_RESULT enumerator defined in the xio.h ]*/
                        ASSERT_IO_SEND_CALLBACK(true, IO_SEND_ERROR);

                        if (test_point == TP_SSL_write_TIMEOUT_FAIL)
                        {
                            /* Tests_RS_TLSIO_OPENSSL_COMPACT_30_073: [ The tlsio_openssl_compact_send shall spend no longer than the internally defined SSL_MAX_BLOCK_TIME_SECONDS (20 seconds) attempting to perform the SSL_write operation. ]*/
                            time_t elapsed = time(NULL) - send_start_time;
                            printf("TP_SSL_write_TIMEOUT_FAIL time expected approx %u seconds, is %u seconds\n", SSL_MAX_BLOCK_TIME_SECONDS, (unsigned int)elapsed);
                            if (elapsed < SSL_MAX_BLOCK_TIME_SECONDS || elapsed > SSL_MAX_BLOCK_TIME_SECONDS + 2)
                            {
                                ASSERT_FAIL("Unexpected timeout elapsed time");
                            }
                        }
                    }
                }
                // End send
                /////////////////////////////////////////////////////////////////////////////////////////////////////

                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // The DoWork test points
                //      TP_SSL_read_NULL_TLSIO_FAIL
                //      TP_SSL_read_OK
                //
                // The SSL_read call never returns failures, so it doesn't allow for much testing
                if (test_point == TP_SSL_read_NULL_TLSIO_FAIL || test_point == TP_SSL_read_OK)
                {
                    reset_callback_context_records();

                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_048: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_dowork shall do nothing except log an error. ]*/
                    CONCRETE_IO_HANDLE tlsio_for_do_work = test_point == TP_SSL_read_NULL_TLSIO_FAIL ? 0 : tlsio;

                    tlsio_id->concrete_io_dowork(tlsio_for_do_work);
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_006: [ The tlsio_openssl_compact shall return the status of all async operations using the callbacks. ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_049: [ If the ssl client is able to provide received data, the tlsio_openssl_compact_dowork shall read this data and call on_bytes_received with the pointer to the buffer containing the data and the number of bytes received. ]*/
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_050: [ When tlsio_openssl_compact_dowork calls on_bytes_received, it shall pass the on_bytes_received_context handle as a parameter. ]*/
                    ASSERT_BYTES_RECEIVED_CALLBACK(test_point == TP_SSL_read_OK);
                }
                // End do work
                /////////////////////////////////////////////////////////////////////////////////////////////////////

                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // The Close test points
                //      TP_Close_NULL_TLSIO_FAIL
                //      TP_Close_no_callback_OK
                //      TP_Close_when_closed_OK
                //

                // Some of the test points don't want or need close here
                bool do_normal_teardown = true;
                switch (test_point)
                {
                    case TP_SSL_write_FAIL:
                    case TP_Destroy_without_close_OK:
                    case TP_SSL_write_TIMEOUT_FAIL:
                        do_normal_teardown = false;
                        break;
                }

                // The main close call is used by the main test sequence, so it's easier to put
                // these unusual close calls here.
                if (test_point == TP_Close_NULL_TLSIO_FAIL || test_point == TP_Close_when_closed_OK)
                {
                    CONCRETE_IO_HANDLE tlsio_for_close = test_point == TP_Close_NULL_TLSIO_FAIL ? NULL : tlsio;
                    tlsio_id->concrete_io_close(tlsio_for_close, NULL, NULL);
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_034: [ The tlsio_openssl_compact_close shall forcibly close any existing ssl connection. ] */
                    if (test_point != TP_Close_NULL_TLSIO_FAIL)
                    {
                        ASSERT_TLSIO_NOT_OPEN(tlsio);
                    }
                }

                // Some of the earlier test point sequences may have called close already or a lack of
                // teardown is part of what's being tested, so they don't all need to be torn down.
                if (do_normal_teardown)
                {
                    ON_IO_CLOSE_COMPLETE close_callback = test_point != TP_Close_no_callback_OK ? on_io_close_complete : NULL;
                    if (open_result == 0)
                    {
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_035: [ The tlsio_openssl_compact_close return value shall be 0 except as noted in the next requirement. ] */
                        int close_return = tlsio_id->concrete_io_close(tlsio, close_callback, IO_CLOSE_COMPLETE_CONTEXT);
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_034: [ The tlsio_openssl_compact_close shall forcibly close any existing ssl connection. ] */
                        ASSERT_TLSIO_NOT_OPEN(tlsio);

                        if (test_point == TP_Close_when_closed_OK)
                        {
                            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_035: [ The tlsio_openssl_compact_close return value shall be 0 except as noted in the next requirement. ] */
                            ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, close_return, "Unexpected close success value");
                        }
                        else
                        {
                            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_036: [ If tlsio_openssl_compact_open has not been called then tlsio_openssl_compact_close shall log an error and return FAILURE. ] */
                            /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_060: [ If tlsio_openssl_compact_open has been called but the process of opening has not been completed, then the on_io_open_complete callback shall be made with IO_SEND_CANCELLED. ] */
                            ASSERT_ARE_EQUAL_WITH_MSG(int, 0, close_return, "Unexpected close fail return value");
                        }
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_037: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall call on_io_close_complete. ] */
                        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_038: [ If on_io_close_complete is provided, tlsio_openssl_compact_close shall pass the callback_context handle into the on_io_close_complete call. ] */
                        ASSERT_IO_CLOSE_CALLBACK(test_point != TP_Close_no_callback_OK);
                    }
                }
                // End close
                /////////////////////////////////////////////////////////////////////////////////////////////////////

                /////////////////////////////////////////////////////////////////////////////////////////////////////
                // The Destroy test points
                //      TP_Destroy_NULL_TLSIO_FAIL
                //      TP_Destroy_without_close_OK
                //      TP_FINAL_OK
                //
                if (test_point == TP_Destroy_NULL_TLSIO_FAIL)
                {
                    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_016: [ If tlsio_handle is NULL, tlsio_openssl_compact_destroy shall do nothing. ] */
                    tlsio_id->concrete_io_destroy(NULL);
                }
                tlsio_id->concrete_io_destroy(tlsio);

                // End Destroy
                /////////////////////////////////////////////////////////////////////////////////////////////////////
            }

            /////////////////////////////////////////////////////////////////////////////////////////////////////
            /////////////////////////////////////////////////////////////////////////////////////////////////////
            ///assert
            /////////////////////////////////////////////////////////////////////////////////////////////////////
            /////////////////////////////////////////////////////////////////////////////////////////////////////

            // The assert section is sparse because most of the assertions have been done in the "act" stage.

            /**
            * The follow assert will compare the expected calls with the actual calls. If it is different,
            *    it will show the serialized strings with the differences in the log.
            */
            if (test_point != TP_SSL_connect_TIMEOUT_FAIL && test_point != TP_SSL_write_TIMEOUT_FAIL)
            {
                ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
            }

            ///cleanup
            umock_c_negative_tests_deinit();

        }
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
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
