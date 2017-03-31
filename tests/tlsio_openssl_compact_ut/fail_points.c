// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file is made an integral part of tlsio_openssl_compact.c with a #include. It
// is broken out for readability. 



// This is a list of all the possible fail points plus the various happy paths for a 
// create/open/close/destroy sequence. 
// Fail points that look like XXXXX_OK are actually a success path. If there is no
// "_OK" in the name, then that fail point is an expected failure.
// Fail points that look like XXXXX_1 or XXXXX_OK_1 are one of a group of different ways
// to either succeed or fail at that fail point
enum
{
						// tlsio_openssl_create

	FP_NULL_CONFIG,		// supplying a null tlsio config to create
	FP_DNS,				// DNS lookup fails
	FP_TLSIO_MALLOC,	// tlsio instance malloc fails
						// Create has succeeded here

						// tlsio_openssl_open
	FP_SOCKET_OPEN,		// creation of the TLS socket fails
	FP_SSL_CTX_new,		// SSL_CTX_new fails
	FP_SSL_new,			// SSL_new fails
	FP_SSL_set_fd,		// SSL_set_fd fails
	FP_SSL_connect_0,	// SSL_connect fails with SSL failure sequence 0


	FP_FINAL_OK
};

typedef struct X {
	int fp;
	const char* name;
} X;

#define FAIL_POINT_NAME(p) { p, #p },

static X fail_point_names[] =
{
	FAIL_POINT_NAME(FP_NULL_CONFIG)
	FAIL_POINT_NAME(FP_DNS)
	FAIL_POINT_NAME(FP_TLSIO_MALLOC)
	FAIL_POINT_NAME(FP_SOCKET_OPEN)
	FAIL_POINT_NAME(FP_SSL_CTX_new)
	FAIL_POINT_NAME(FP_SSL_new)
	FAIL_POINT_NAME(FP_SSL_set_fd)
	FAIL_POINT_NAME(FP_SSL_connect_0)

	FAIL_POINT_NAME(FP_FINAL_OK)
};

static void fail_point_label_output(int fp)
{
	printf("\n\nFail point: %d  %s\n", fp, fail_point_names[fp].name);
}


// fail_points is a lookup table that provides an index 
// to pass to umock_c_negative_tests_fail_call(0) given
// a provided fail point enum value. If the index is 255,
// that means don't call umock_c_negative_tests_fail_call().
static uint16_t fail_points[FP_FINAL_OK + 1];
static uint16_t expected_call_count = 0;


static void InitFailPoints()
{

	expected_call_count = 0;
	memset(fail_points, 0xff, sizeof(fail_points));

}


// FAIL_POINT means that the call is expected at the provided fail point and beyond,
// and the framework will fail the call the first time it hits it.
// The messy macro on line 2 of FAIL_POINT is the expansion of STRICT_EXPECTED_CALL
#define FAIL_POINT(fp, call) if(fail_point >= fp) {  \
	C2(get_auto_ignore_args_function_, call)(C2(umock_c_strict_expected_,call), #call);			\
	fail_points[fp] = expected_call_count;	\
	expected_call_count++;		\
}

// NO_FAIL_POINT means that this call is expected at the provided fail point and beyond,
// and the framework will not fail the call.
// The messy macro on line 2 of NO_FAIL_POINT is the expansion of STRICT_EXPECTED_CALL
#define NO_FAIL_POINT(fp, call) if(fail_point >= fp) {  \
	C2(get_auto_ignore_args_function_, call)(C2(umock_c_strict_expected_,call), #call);			\
	expected_call_count++;		\
}

// IF_PAST_FAIL_POINT means that this call is expected everywhere past the provided
// failure point, and the framework will not fail the call.
// The messy macro on line 2 of IF_PAST_FAIL_POINT is the expansion of STRICT_EXPECTED_CALL
#define IF_PAST_FAIL_POINT(fp, call) if(fail_point > fp) {  \
	C2(get_auto_ignore_args_function_, call)(C2(umock_c_strict_expected_,call), #call);			\
	expected_call_count++;		\
}
