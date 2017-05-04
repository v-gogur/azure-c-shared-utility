
// Copyright(c) Microsoft.All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file is made an integral part of tlsio_openssl_compact.c with a #include. It
// is broken out for readability. 

/////////////////////////////////////////////////////////////////////
//  Empty functions. These must be available to call, but they have no effect
int TLSv1_2_client_method() { return 0; }
void SSL_CTX_set_default_read_buffer_len(SSL_CTX* dummy, int dummy2) { dummy; dummy2; }

// The timeout tests only run manually under Windows
#ifdef UNIT_TEST_RUN_TIMEOUT_TESTS
#include <Windows.h>
#endif
void ThreadAPI_Sleep(unsigned int milliseconds) 
{ 
#ifdef UNIT_TEST_RUN_TIMEOUT_TESTS
    Sleep(milliseconds);
#else
    milliseconds; return; 
#endif  // UNIT_TEST_RUN_TIMEOUT_TESTS
}
// End of empty functions
/////////////////////////////////////////////////////////////////////



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

static int on_bytes_received_call_count;
static bool on_bytes_received_context_ok;

// Context pointers for the callbacks
#define IO_OPEN_COMPLETE_CONTEXT (void*)55
#define IO_ERROR_CONTEXT (void*)66
#define IO_BYTES_RECEIVED_CONTEXT (void*)77
#define IO_CLOSE_COMPLETE_CONTEXT (void*)231
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
    on_bytes_received_call_count = 0;
    on_bytes_received_context_ok = false;
}

// Callbacks used by the tlsio adapter

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
/* Tests_SRS_TLSIO_OPENSSL_COMPACT_30_042: [ The tlsio_openssl_compact_dowork shall supply the provided callback_context when it calls on_send_complete. ]*/
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
    on_bytes_received_call_count++;
    // There's no interesting tlsio behavior to test with
    // varying message lengths, so we'll just use a tiny one.
    //buffer[0] = 4;
    //buffer[1] = 2;
    //return 2;
    on_bytes_received_context_ok = context == IO_BYTES_RECEIVED_CONTEXT;
    ASSERT_ARE_EQUAL(int, 4, (int)buffer[0]);
    ASSERT_ARE_EQUAL(int, 2, (int)buffer[1]);
    ASSERT_ARE_EQUAL(int, 2, (int)size);
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

static void ASSERT_BYTES_RECEIVED_CALLBACK(bool called)
{
    if (called)
    {
        ASSERT_ARE_EQUAL_WITH_MSG(int, 1, on_bytes_received_call_count, "bytes_received_callback count mismatch");
        ASSERT_IS_TRUE_WITH_MSG(on_bytes_received_context_ok, "bytes_received_context not passed");
    }
    else
    {
        ASSERT_ARE_EQUAL_WITH_MSG(int, 0, on_bytes_received_call_count, "unexpected bytes_received_callback");
    }
}
