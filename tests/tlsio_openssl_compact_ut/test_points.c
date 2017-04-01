// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file is made an integral part of tlsio_openssl_compact.c with a #include. It
// is broken out for readability. 



// This is a list of all the possible test points plus the various happy paths for a 
// create/open/close/destroy sequence. 
// Test points that look like XXXXX_OK are actually a success path. If there is no
// "_OK" in the name, then that test point is an expected failure.
// Test points that look like XXXXX_1 or XXXXX_OK_1 are one of a group of different ways
// to either succeed or fail at that test point
enum
{
							// tlsio_openssl_create

	TP_NULL_CONFIG_FAIL,	// supplying a null tlsio config to create
	TP_DNS_FAIL,			// DNS lookup fails
	TP_TLSIO_MALLOC_FAIL,	// tlsio instance malloc fails
							// Create has succeeded here

							// tlsio_openssl_open
	TP_SOCKET_OPEN_FAIL,	// creation of the TLS socket fails
	TP_SSL_CTX_new_FAIL,	// SSL_CTX_new fails
	TP_SSL_new_FAIL,		// SSL_new fails
	TP_SSL_set_fd_FAIL,		// SSL_set_fd fails
	TP_SSL_connect_0_FAIL,	// SSL_connect fails with failure sequence 0
	TP_SSL_connect_1_FAIL,	// SSL_connect fails with failure sequence 1
	TP_SSL_connect_0_OK,	// SSL_connect fails with success sequence 0
	TP_SSL_connect_1_OK,	// SSL_connect fails with success sequence 1
	TP_Open_no_callback,	// Open succeeded but no on_open callback privided


	TP_Close_no_callback,	// Calling close with no close callback function

	// NOTE!!!! Update test_point_names below when adding to this enum

	TP_FINAL_OK
};

typedef struct X {
	int fp;
	const char* name;
} X;

#define TEST_POINT_NAME(p) { p, #p },

static X test_point_names[] =
{
	TEST_POINT_NAME(TP_NULL_CONFIG_FAIL)
	TEST_POINT_NAME(TP_DNS_FAIL)
	TEST_POINT_NAME(TP_TLSIO_MALLOC_FAIL)
	TEST_POINT_NAME(TP_SOCKET_OPEN_FAIL)
	TEST_POINT_NAME(TP_SSL_CTX_new_FAIL)
	TEST_POINT_NAME(TP_SSL_new_FAIL)
	TEST_POINT_NAME(TP_SSL_set_fd_FAIL)
	TEST_POINT_NAME(TP_SSL_connect_0_FAIL)
	TEST_POINT_NAME(TP_SSL_connect_1_FAIL)
	TEST_POINT_NAME(TP_SSL_connect_0_OK)
	TEST_POINT_NAME(TP_SSL_connect_1_OK)
	TEST_POINT_NAME(TP_Open_no_callback)


	TEST_POINT_NAME(TP_Close_no_callback)

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

// IF_PAST_TEST_POINT means that this call is expected everywhere past the provided
// test point, and the framework will not fail the call.
// The messy macro on line 2 of IF_PAST_TEST_POINT is the expansion of STRICT_EXPECTED_CALL
#define IF_PAST_TEST_POINT(fp, call) if(test_point > fp) {  \
	C2(get_auto_ignore_args_function_, call)(C2(umock_c_strict_expected_,call), #call);			\
	expected_call_count++;		\
}
