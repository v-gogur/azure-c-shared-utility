// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file is made an integral part of tlsio_openssl_compact.c with a #include. It
// is broken out for readability. 

// 
#define SSL_ERROR_HARD_FAIL 99
#define SSL_Good_Ptr (void*)22
#define SSL_Good_Context_Ptr (SSL_CTX*)33
#define SSL_Good_Socket 44

#define SSL_Get_IPv4_OK (uint32_t)0x11223344
#define SSL_Get_IPv4_FAIL 0

#define SSL_goood_port_number  447
const char* const SSL_goood_host_name = "fakehost.com";

// The asynchronous nature of SSL_write and SSL_connect means that they must 
// produce several combinations of results within a single test pass.
// This is because some of the "errors" they produce are real errors and the
// system should give up and fail, while other "errors" really mean "I'm not
// done yet and you should call me again immediately". Of course, they can
// also produce success as well. This is all too complicated for the 
// standard umock framework, so this file manages the SSL errors


// Error sequences are composed of pairs of the main error return plus
// an extended error returned by SSL_get_error()
typedef struct SSL_error_pair {
	int main;
	int extended;
	bool isFinalSuccess;
} SSL_error_pair;

static int SSL_error_sequence_current_main_index = 0;
static int SSL_error_sequence_current_extended_index = 0;
static int SSL_error_sequence_current_size = 0;
static SSL_error_pair* SSL_error_current_sequence = NULL;

enum
{
	SSL_CONNECT_ERROR_SEQUENCE_0,
	SSL_CONNECT_ERROR_SEQUENCE_1,
	SSL_CONNECT_OK_ERROR_SEQUENCE_0,
	SSL_CONNECT_OK_ERROR_SEQUENCE_1,
};

static SSL_error_pair SSL_CONNECT_ERROR_SEQUENCE_0_impl[] =
{
	{ -1, SSL_ERROR_HARD_FAIL, false }
};

static SSL_error_pair SSL_CONNECT_ERROR_SEQUENCE_1_impl[] =
{
	{ -1, SSL_ERROR_WANT_READ, false },
	{ -1, SSL_ERROR_WANT_WRITE, false },
	{ -1, SSL_ERROR_HARD_FAIL, false },
};

void SSL_ERROR_ASSERT_RECENT_SEQUENCE()
{
	if (SSL_error_sequence_current_main_index != SSL_error_sequence_current_size ||
		SSL_error_sequence_current_extended_index != SSL_error_sequence_current_size)
	{
		ASSERT_FAIL("SSL_ERROR_ASSERT_RECENT_SEQUENCE failure");
	}
}

#define SSL_ERROR_SEQUENCE_CASE_ENTRY(seq)

void SSL_ERROR_PREPARE_SEQUENCE(int sequence)
{
	// The initial state must be correct also
	SSL_ERROR_ASSERT_RECENT_SEQUENCE();
	SSL_error_sequence_current_main_index = 0;
	SSL_error_sequence_current_extended_index = 0;
	switch (sequence)
	{
	case SSL_CONNECT_ERROR_SEQUENCE_0: 
		SSL_error_current_sequence = SSL_CONNECT_ERROR_SEQUENCE_0_impl;  
		SSL_error_sequence_current_size = sizeof(SSL_CONNECT_ERROR_SEQUENCE_0_impl) / sizeof(SSL_error_pair);
		break;

		// this is a program bug
	default: ASSERT_IS_FALSE(true);
		break;
	}
}

static int my_SSL_connect(SSL* ssl)
{
	ASSERT_ARE_EQUAL(int, (int)ssl, (int)SSL_Good_Ptr);
	int result = SSL_error_current_sequence[SSL_error_sequence_current_main_index].main;
	if (SSL_error_current_sequence[SSL_error_sequence_current_main_index].isFinalSuccess)
	{
		// SSL_get_error will not get called since we're succeeding here, so
		// increment SSL_error_sequence_current_extended_index to satisfy  
		// SSL_ERROR_ASSERT_RECENT_SEQUENCE that things are as expected.
		SSL_error_sequence_current_extended_index++;
	}
	SSL_error_sequence_current_main_index++;
	return result;
}

// SSL_get_error is guaranteed to be called after every non-successful
// call to my_SSL_connect.
int SSL_get_error(SSL* ssl, int last_error)
{
	last_error;
	ASSERT_ARE_EQUAL(int, (int)ssl, (int)SSL_Good_Ptr);
	int result = SSL_error_current_sequence[SSL_error_sequence_current_extended_index].extended;
	SSL_error_sequence_current_extended_index++;
	return result;
}
