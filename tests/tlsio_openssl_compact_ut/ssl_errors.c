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
uint8_t* SSL_send_buffer = (uint8_t*)"111111112222222233333333";

// The asynchronous nature of SSL_write and SSL_connect means that they must 
// produce several combinations of results within a single test pass.
// This is because some of the "errors" they produce are real errors and the
// system should give up and fail, while other "errors" really mean "I'm not
// done yet and you should call me again immediately". Of course, they can
// also produce success as well. This is all too complicated for the 
// standard umock framework, so this file manages the SSL errors


// Error sequences are composed of pairs of the main error return plus
// an extended error returned by SSL_get_error()
typedef struct SSL_error_pair 
{
    int main;
    int extended;
    bool isFinalSuccess;
} SSL_error_pair;

typedef struct SSL_error_sequence
{
    int main_index;
    int extended_index;
    int size;
    SSL_error_pair* sequence;
} SSL_error_sequence;

static  SSL_error_sequence SSL_connect_error_sequence = { 0, 0, 0, NULL };
static  SSL_error_sequence SSL_write_error_sequence = { 0, 0, 0, NULL };
static SSL_error_sequence* current_ssl_get_error_sequence = &SSL_connect_error_sequence;

enum
{
    SSL_CONNECT_FAIL_ERROR_SEQUENCE_0,
    SSL_CONNECT_FAIL_ERROR_SEQUENCE_1,
    SSL_CONNECT_OK_ERROR_SEQUENCE_0,
    SSL_CONNECT_OK_ERROR_SEQUENCE_1,
    SSL_WRITE_FAIL_ERROR_SEQUENCE,
    SSL_WRITE_OK_ERROR_SEQUENCE,
};

static SSL_error_pair SSL_CONNECT_FAIL_ERROR_SEQUENCE_0_impl[] =
{
    { -1, SSL_ERROR_HARD_FAIL, false }
};

static SSL_error_pair SSL_CONNECT_FAIL_ERROR_SEQUENCE_1_impl[] =
{
    { -1, SSL_ERROR_WANT_READ, false },
    { -1, SSL_ERROR_WANT_WRITE, false },
    { -1, SSL_ERROR_HARD_FAIL, false },
};

static SSL_error_pair SSL_CONNECT_OK_ERROR_SEQUENCE_0_impl[] =
{
    { 0, 0, true }		// success
};

static SSL_error_pair SSL_CONNECT_OK_ERROR_SEQUENCE_1_impl[] =
{
    { -1, SSL_ERROR_WANT_READ, false },
    { -1, SSL_ERROR_WANT_WRITE, false },
    { 0, 0, true },		// success
};

// Assumes input of "11111111222222223333";
static SSL_error_pair SSL_WRITE_FAIL_ERROR_SEQUENCE_impl[] =
{
    { -1, SSL_ERROR_WANT_READ, false },
    { -1, SSL_ERROR_WANT_WRITE, false },
    { 8, 0, true },		// success
    { -1, SSL_ERROR_WANT_READ, false },
    { -1, SSL_ERROR_WANT_WRITE, false },
    { 8, 0, true },		// success
    { -1, SSL_ERROR_WANT_READ, false },
    { -1, SSL_ERROR_WANT_WRITE, false },
    { -1, SSL_ERROR_HARD_FAIL, false },
};

// Assumes input of "11111111222222223333";
/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_040: [ The tlsio_openssl_compact_send shall send the first size bytes in buffer to the ssl connection. ]*/
/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_043: [ if the ssl was not able to send all data in the buffer, the tlsio_openssl_compact_send shall call the ssl again to send the remaining bytes. ]*/
static SSL_error_pair SSL_WRITE_OK_ERROR_SEQUENCE_impl[] =
{
    { -1, SSL_ERROR_WANT_READ, false },
    { -1, SSL_ERROR_WANT_WRITE, false },
    { 8, 0, true },		// success
    { -1, SSL_ERROR_WANT_READ, false },
    { -1, SSL_ERROR_WANT_WRITE, false },
    { 8, 0, true },		// success
    { -1, SSL_ERROR_WANT_READ, false },
    { -1, SSL_ERROR_WANT_WRITE, false },
    { 4, 0, true },		// success
};

/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_040: [ The tlsio_openssl_compact_send shall send the first size bytes in buffer to the ssl connection. ]*/
/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_043: [ if the ssl was not able to send all data in the buffer, the tlsio_openssl_compact_send shall call the ssl again to send the remaining bytes. ]*/
int my_SSL_write(SSL* ssl, uint8_t* buffer, size_t size)
{
    ASSERT_ARE_EQUAL(int, (int)ssl, (int)SSL_Good_Ptr);
    int result = SSL_write_error_sequence.sequence[SSL_write_error_sequence.main_index].main;
    if (SSL_write_error_sequence.sequence[SSL_write_error_sequence.main_index].isFinalSuccess)
    {
        // SSL_get_error will not get called since we're succeeding here, so
        // increment SSL_error_sequence_current_extended_index to satisfy  
        // SSL_ERROR_ASSERT_RECENT_SEQUENCE that things are as expected.
        SSL_write_error_sequence.extended_index++;
    }
    SSL_write_error_sequence.main_index++;
    buffer;
    size;
    return result;
}


void SSL_ERROR_ASSERT_LAST_ERROR_SEQUENCE(SSL_error_sequence* seq)
{
    if (seq->main_index != seq->size ||
        seq->extended_index != seq->size)
    {
        ASSERT_FAIL("SSL_ERROR_ASSERT_RECENT_SEQUENCE failure");
    }
}

void SSL_CONNECT_ERROR_ASSERT_LAST_ERROR_SEQUENCE()
{
    SSL_ERROR_ASSERT_LAST_ERROR_SEQUENCE(&SSL_connect_error_sequence);
}

void SSL_WRITE_ERROR_ASSERT_LAST_ERROR_SEQUENCE()
{
    SSL_ERROR_ASSERT_LAST_ERROR_SEQUENCE(&SSL_write_error_sequence);
}

#define SSL_ERROR_SEQUENCE_CASE_ENTRY(s) \
    case s :		\
    seq->sequence = s ## _impl;		\
    seq->size = sizeof(s ## _impl) / sizeof(SSL_error_pair);		\
    break

void SSL_CONNECT_ERROR_PREPARE_SEQUENCE(int sequence)
{
    // The initial state must be correct also
    SSL_error_sequence* seq = &SSL_connect_error_sequence;
    SSL_ERROR_ASSERT_LAST_ERROR_SEQUENCE(seq);
    seq->main_index = 0;
    seq->extended_index = 0;
    switch (sequence)
    {
        SSL_ERROR_SEQUENCE_CASE_ENTRY(SSL_CONNECT_FAIL_ERROR_SEQUENCE_0);
        SSL_ERROR_SEQUENCE_CASE_ENTRY(SSL_CONNECT_FAIL_ERROR_SEQUENCE_1);
        SSL_ERROR_SEQUENCE_CASE_ENTRY(SSL_CONNECT_OK_ERROR_SEQUENCE_0);
        SSL_ERROR_SEQUENCE_CASE_ENTRY(SSL_CONNECT_OK_ERROR_SEQUENCE_1);

        // this is a program bug
    default:
        ASSERT_FAIL("Unexpected value in SSL_CONNECT_ERROR_PREPARE_SEQUENCE");
        break;
    }
}

void SSL_WRITE_ERROR_PREPARE_SEQUENCE(int sequence)
{
    // The initial state must be correct also
    SSL_error_sequence* seq = &SSL_write_error_sequence;
    SSL_ERROR_ASSERT_LAST_ERROR_SEQUENCE(seq);
    seq->main_index = 0;
    seq->extended_index = 0;
    switch (sequence)
    {
        SSL_ERROR_SEQUENCE_CASE_ENTRY(SSL_WRITE_FAIL_ERROR_SEQUENCE);
        SSL_ERROR_SEQUENCE_CASE_ENTRY(SSL_WRITE_OK_ERROR_SEQUENCE);

        // this is a program bug
    default:
        ASSERT_FAIL("Unexpected value in SSL_WRITE_ERROR_PREPARE_SEQUENCE");
        break;
    }
}

void ACTIVATE_SSL_CONNECT_ERROR_SEQUENCE()
{
    current_ssl_get_error_sequence = &SSL_connect_error_sequence;
}

void ACTIVATE_SSL_WRITE_ERROR_SEQUENCE()
{
    current_ssl_get_error_sequence = &SSL_write_error_sequence;
}

static int my_SSL_connect(SSL* ssl)
{
    ASSERT_ARE_EQUAL(int, (int)ssl, (int)SSL_Good_Ptr);
    int result = SSL_connect_error_sequence.sequence[SSL_connect_error_sequence.main_index].main;
    if (SSL_connect_error_sequence.sequence[SSL_connect_error_sequence.main_index].isFinalSuccess)
    {
        // SSL_get_error will not get called since we're succeeding here, so
        // increment SSL_error_sequence_current_extended_index to satisfy  
        // SSL_ERROR_ASSERT_RECENT_SEQUENCE that things are as expected.
        SSL_connect_error_sequence.extended_index++;
    }
    SSL_connect_error_sequence.main_index++;
    return result;
}

int my_SSL_read(SSL* ssl, uint8_t* buffer, size_t size)
{
    size;
    ASSERT_ARE_EQUAL(int, (int)ssl, (int)SSL_Good_Ptr);
    // There's no interesting tlsio behavior to test with
    // varying message lengths, so we'll just use a tiny one.
    buffer[0] = 4;
    buffer[1] = 2;
    return 2;
}

// SSL_get_error is guaranteed to be called after every non-successful
// call to my_SSL_connect.
int SSL_get_error(SSL* ssl, int last_error)
{
    last_error;
    ASSERT_ARE_EQUAL(int, (int)ssl, (int)SSL_Good_Ptr);
    int result = current_ssl_get_error_sequence->sequence[current_ssl_get_error_sequence->extended_index].extended;
    current_ssl_get_error_sequence->extended_index++;
    return result;
}
