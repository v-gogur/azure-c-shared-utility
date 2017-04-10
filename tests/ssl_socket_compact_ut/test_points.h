// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file is made an integral part of ssl_socket_compact.c with a #include. It
// is broken out for readability. 



// This is a list of all the possible test points pfor a create sequence. 
// Test points that look like XXXXX_OK are actually a success path. If there is no
// "_OK" in the name, then that test point is an expected failure.
// Test points that look like XXXXX_1 or XXXXX_OK_1 are one of a group of different ways
// to either succeed or fail at that test point
enum
{
    TP_SOCKET_CREATE,	        // socket creation
    TP_SETOPTION_0,			    // the first setoption call
    TP_SETOPTION_1,	            // the second setoption call
    TP_SETOPTION_2,	            // the third setoption call
    TP_SETOPTION_3,	            // the fourth setoption call
    TP_BIND,	                // the bind call
    TP_CONNECT,	                // the connect call
    TO_SELECT,	                // the select call
    TO_FD_ISSET,                // the FD_ISSET call
    // NOTE!!!! Update test_point_names below when adding to this enum
    TP_FINAL_OK     // Always keep as last entry
};

typedef struct X {
    int fp;
    const char* name;
} X;

#define TEST_POINT_NAME(p) { p, #p },

// The list of test_point_names is to help human-readability of the output
static X test_point_names[] =
{
    TEST_POINT_NAME(TP_SOCKET_CREATE)
    TEST_POINT_NAME(TP_SETOPTION_0)
    TEST_POINT_NAME(TP_SETOPTION_1)
    TEST_POINT_NAME(TP_SETOPTION_2)
    TEST_POINT_NAME(TP_SETOPTION_3)
    TEST_POINT_NAME(TP_BIND)
    TEST_POINT_NAME(TP_CONNECT)
    TEST_POINT_NAME(TO_SELECT)
    TEST_POINT_NAME(TO_FD_ISSET)
    TEST_POINT_NAME(TP_FINAL_OK)
};

static void test_point_label_output(int fp)
{
    printf("\n\nTest point: %d  %s\n", fp, test_point_names[fp].name);
}


// test_points is a lookup table that provides an index 
// to pass to umock_c_negative_tests_fail_call(0) given
// a provided fail point enum value. If the index is 255,
// that means don't call umock_c_negative_tests_fail_call().
static uint16_t test_points[TP_FINAL_OK + 1];
static uint16_t expected_call_count = 0;


static void InitTestPoints()
{
    expected_call_count = 0;
    memset(test_points, 0xff, sizeof(test_points));
}


// TEST_POINT means that the call is expected at the provided fail point and beyond,
// and the framework will fail the call the first time it hits it.
// The messy macro on line 2 of TEST_POINT is the expansion of STRICT_EXPECTED_CALL
#define TEST_POINT(fp, call) if(test_point >= fp) {  \
    C2(get_auto_ignore_args_function_, call)(C2(umock_c_strict_expected_,call), #call);			\
    test_points[fp] = expected_call_count;	\
    expected_call_count++;		\
}

// NO_FAIL_TEST_POINT means that this call is expected at the provided test point and beyond,
// and the framework will not fail the call.
// The messy macro on line 2 of NO_FAIL_TEST_POINT is the expansion of STRICT_EXPECTED_CALL
#define NO_FAIL_TEST_POINT(fp, call) if(test_point >= fp) {  \
    C2(get_auto_ignore_args_function_, call)(C2(umock_c_strict_expected_,call), #call);			\
    expected_call_count++;		\
}

// TEAR_DOWN_POINT means that this call is expected everywhere past the provided
// test point, and the framework will not fail the call. The semantics of this call are only
// slightly different from NO_FAIL_TEST_POINT, but this semantic improves readability
// for setting up calls such as Close which are part of a tear-down process.
// The messy macro on line 2 of TEAR_DOWN_POINT is the expansion of STRICT_EXPECTED_CALL
#define TEAR_DOWN_POINT(fp, call) if(test_point > fp) {  \
    C2(get_auto_ignore_args_function_, call)(C2(umock_c_strict_expected_,call), #call);			\
    expected_call_count++;		\
}
