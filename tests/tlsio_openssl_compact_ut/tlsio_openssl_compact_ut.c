// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#endif

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
#include "umocktypes_bool.h"
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
#include "azure_c_shared_utility/dns.h"
#include "azure_c_shared_utility/socket_async.h"
#include "openssl/ssl.h"
#undef ENABLE_MOCKS

static int bool_Compare(bool left, bool right)
{
    return left != right;
}

static void bool_ToString(char* string, size_t bufferSize, bool val)
{
    (void)bufferSize;
    (void)strcpy(string, val ? "true" : "false");
}

#ifndef __cplusplus
static int _Bool_Compare(_Bool left, _Bool right)
{
    return left != right;
}

static void _Bool_ToString(char* string, size_t bufferSize, _Bool val)
{
    (void)bufferSize;
    (void)strcpy(string, val ? "true" : "false");
}
#endif

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
        REGISTER_UMOCK_ALIAS_TYPE(uint32_t, unsigned int);
        REGISTER_UMOCK_ALIAS_TYPE(uint16_t, unsigned short);

        REGISTER_GLOBAL_MOCK_RETURNS(DNS_Get_IPv4, SSL_Get_IPv4_OK, SSL_Get_IPv4_FAIL);
        REGISTER_GLOBAL_MOCK_RETURNS(socket_async_create, SSL_Good_Socket, -1);

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

    TEST_FUNCTION(tlsio_openssl__create_parameter_validation_fails__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        TLSIO_CONFIG config[4];
        create_parameters_t p[4];
        populate_create_parameters(p + 0, NULL,       SSL_good_host_name, SSL_good_port_number, "Should fail with NULL config");
        populate_create_parameters(p + 1, config + 1, NULL,               SSL_good_port_number, "Should fail with NULL hostname");
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

    TEST_FUNCTION(tlsio_openssl__create_unhappy_paths__fails)
    {
        ///arrange
        int negativeTestsInitResult = umock_c_negative_tests_init();
        ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        TLSIO_CONFIG config = { SSL_good_host_name, SSL_good_port_number, NULL, NULL };

        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // concrete_io struct
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // copy hostname
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // singlylinkedlist_create
        umock_c_negative_tests_snapshot();

        // Skip the failing of the first call
        for (unsigned int i = 0; i < umock_c_negative_tests_call_count(); i++)
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(i);

            ///act
            CONCRETE_IO_HANDLE result = tlsio_id->concrete_io_create(&config);

            ///assert
            ASSERT_IS_NULL(result);
        }

        ///cleanup
        umock_c_negative_tests_deinit();
    }

    TEST_FUNCTION(tlsio_openssl__create__succeeds)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        TLSIO_CONFIG config = { SSL_good_host_name, SSL_good_port_number, NULL, NULL };

        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // concrete_io struct
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // copy hostname
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG));  // singlylinkedlist_create

        ///act
        CONCRETE_IO_HANDLE result = tlsio_id->concrete_io_create(&config);

        ///assert
        ASSERT_IS_NOT_NULL(result);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        ///cleanup
        tlsio_id->concrete_io_destroy(result);
    }

    TEST_FUNCTION(tlsio_openssl__open_parameter_validation_fails__fails)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        TLSIO_CONFIG config = { SSL_good_host_name, SSL_good_port_number, NULL, NULL };

        // Parameters arrays
        bool p0[OPEN_PV_COUNT];
        ON_IO_OPEN_COMPLETE p1[OPEN_PV_COUNT];
        ON_BYTES_RECEIVED p2[OPEN_PV_COUNT];
        ON_IO_ERROR p3[OPEN_PV_COUNT];
        const char* fm[OPEN_PV_COUNT];

        p0[0] = false; p1[0] = on_io_open_complete; p2[0] = on_bytes_received; p3[0] = on_io_error; fm[0] = "Unexpected open success when tlsio_handle is NULL";
        p0[1] = true; p1[1] = NULL; /*           */ p2[1] = on_bytes_received; p3[1] = on_io_error; fm[1] = "Unexpected open success when on_io_open_complete is NULL";
        p0[2] = true; p1[2] = on_io_open_complete; p2[2] = NULL; /*         */ p3[2] = on_io_error; fm[2] = "Unexpected open success when on_bytes_received is NULL";
        p0[3] = true; p1[3] = on_io_open_complete; p2[3] = on_bytes_received; p3[3] = NULL; /*   */ fm[3] = "Unexpected open success when on_io_error is NULL";

        // Cycle through each failing combo of parameters
        for (int i = 0; i < OPEN_PV_COUNT; i++)
        {
            ///arrange
            CONCRETE_IO_HANDLE tlsio = tlsio_id->concrete_io_create(&config);

            ///act
            int open_result = tlsio_id->concrete_io_open(p0[i] ? tlsio : NULL, p1[i], IO_OPEN_COMPLETE_CONTEXT, p2[i],
                IO_BYTES_RECEIVED_CONTEXT, p3[i], IO_ERROR_CONTEXT);

            ///assert
            ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, open_result, 0, fm[i]);

            ///cleanup
            tlsio_id->concrete_io_destroy(tlsio);
        }
    }

    TEST_FUNCTION(tlsio_openssl__destroy_unopened__succeeds)
    {
        ///arrange
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();
        TLSIO_CONFIG config = { SSL_good_host_name, SSL_good_port_number, NULL, NULL };
        CONCRETE_IO_HANDLE result = tlsio_id->concrete_io_create(&config);
        ASSERT_IS_NOT_NULL(result);
        umock_c_reset_all_calls();

        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_NUM_ARG));  // copy hostname
        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_NUM_ARG));  // singlylinkedlist_create
        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_NUM_ARG));  // concrete_io struct

                                                              ///act
        tlsio_id->concrete_io_destroy(result);

        ///assert
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        ///cleanup
    }

    /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30XX_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
    TEST_FUNCTION(tlsio_openssl__tlsio_get_interface_description)
    {
        ///act
        const IO_INTERFACE_DESCRIPTION* tlsio_id = tlsio_get_interface_description();

        ///assert
        /* Tests_SRS_TLSIO_OPENSSL_COMPACT_30XX_001: [ The tlsio_openssl_compact shall implement and export all the Concrete functions in the VTable IO_INTERFACE_DESCRIPTION defined in the xio.h. ] */
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
