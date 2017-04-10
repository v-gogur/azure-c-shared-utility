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
#include "azure_c_shared_utility/ssl_socket.h"


 // WIN32 sockets are incompatible with other OS socket function signatures,
 // so this adapter isn't designed to function under Windows. 
 // Instead, Windows compilations will be used for unit testing only.
 // Linux unit tests can check positive functionality, and others will just
 // verify that they compile.
#define ENABLE_MOCKS
#include "azure_c_shared_utility/gballoc.h"
#ifdef WIN32
#include "win32_header.h"
#endif // WIN32
#undef ENABLE_MOCKS

#include "test_points.h"

#define GOOD_SOCKET_VALUE 0


#ifdef WIN32	
int fcntl(int socket, int flags, int value) { socket; flags; value; return 0; }
void FD_SET(int sock, void* dummy) { sock; dummy; }
#pragma comment (lib, "Ws2_32.lib")
#endif // WIN32


 /**
  * You can create some global variables that your test will need in some way.
  */
//static void* g_GenericPointer;

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
BEGIN_TEST_SUITE(ssl_socket_compact_ut)

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

        REGISTER_UMOCK_ALIAS_TYPE(uint32_t, unsigned int);

        /**
         * It is necessary to replace all mockable functions by the mock functions that you created here.
         * It will tell the test suite to call my_callee_open besides to call the real callee_open.
         */
		//REGISTER_GLOBAL_MOCK_HOOK(callee_open, my_callee_open);

        /**
         * If you don't care about what there is inside of the function in anyway, and you just need 
         *   to control the function return you can use the REGISTER_GLOBAL_MOCK_RETURN and 
         *   REGISTER_GLOBAL_MOCK_FAIL_RETURN.
         *
         * In the follow example, callee_bar_1 will always return CALLEE_RESULT_OK, so, we don't need to
         *   create the unhappy return; and callee_bar_2 can return CALLEE_RESULT_OK or CALLEE_RESULT_FAIL.
         */
        //REGISTER_GLOBAL_MOCK_RETURN(callee_bar_1, CALLEE_RESULT_OK);
        //REGISTER_GLOBAL_MOCK_RETURN(callee_bar_2, CALLEE_RESULT_OK);
        //REGISTER_GLOBAL_MOCK_FAIL_RETURN(callee_bar_2, CALLEE_RESULT_FAIL);
        REGISTER_GLOBAL_MOCK_RETURNS(socket, GOOD_SOCKET_VALUE, SSL_SOCKET_NULL_SOCKET);
        REGISTER_GLOBAL_MOCK_RETURNS(setsockopt, 0, -1);
        REGISTER_GLOBAL_MOCK_RETURNS(getsockopt, 0, -1);

        /**
         * Or you can combine, for example, in the success case malloc will call my_gballoc_malloc, and for
         *    the failed cases, it will return NULL.
         */
        //REGISTER_GLOBAL_MOCK_FAIL_RETURN(callee_open, NULL);    // Fail return for the callee_open.
        //REGISTER_GLOBAL_MOCK_HOOK(gballoc_malloc, my_gballoc_malloc);
        //REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_malloc, NULL);
        //REGISTER_GLOBAL_MOCK_HOOK(gballoc_realloc, my_gballoc_realloc);
        //REGISTER_GLOBAL_MOCK_FAIL_RETURN(gballoc_realloc, NULL);
        //REGISTER_GLOBAL_MOCK_HOOK(gballoc_free, my_gballoc_free);

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

    // TODO: Add your unit test functions as in the example below:
#if false
    /* Tests_SRS_TEMPLATE_21_001: [ The target_create shall call callee_open to do stuff and allocate the memory. ]*/
    TEST_FUNCTION(target_create_call_callee_open__succeed)
    {
        ///arrange
        TARGET_RESULT result;
        
        /**
         * The STRICT_EXPECTED_CALL creates a list of functions that we expect that the target calls. 
         * The function umock_c_get_expected_calls() returns this list as a serialized string.
         * You can determine all parameters, with the expected value, or define that the argument must
         *    be ignored by the test suite.
         * During the execution, the suit will collect the same information, creating a second list of
         *   called functions.
         * The function umock_c_get_actual_calls() return this list as a serialized string.
         */
        STRICT_EXPECTED_CALL(callee_open(SIZEOF_FOO_MEMORY));
        STRICT_EXPECTED_CALL(gballoc_malloc(SIZEOF_FOO_MEMORY));    //This is the malloc in the mock my_callee_open().
        STRICT_EXPECTED_CALL(gballoc_malloc(IGNORED_NUM_ARG)).IgnoreArgument(1);    //This is the malloc in the target_create().
        STRICT_EXPECTED_CALL(gballoc_free(IGNORED_PTR_ARG)).IgnoreArgument(1);      //This is the free in the target_create().

        ///act
        result = target_create(SIZEOF_FOO_MEMORY);

        ///assert
        ASSERT_ARE_EQUAL(int, TARGET_RESULT_OK, result);
        /**
         * The follow assert will compare the expected calls with the actual calls. If it is different, 
         *    it will show the serialized strings with the differences in the log.
         */
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

        ///cleanup
        target_destroy();
    }
#endif


END_TEST_SUITE(ssl_socket_compact_ut)
