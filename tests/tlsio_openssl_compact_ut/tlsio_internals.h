// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This file is made an integral part of tlsio_openssl_compact.c with a #include. It
// is broken out for readability. 

// This file invades the internal struction of tlsio_openssl_compact.c by reproducing
// the normally hidden TLSIO_STATE and TLS_IO_INSTANCE types 

// This adapter keeps itself in either TLSIO_STATE_OPEN or
// TLSIO_STATE_NOT_OPEN. There are no internally inconsistent
// states that would need to be labeled "error". Failures that
// tell us that the SSL connection can no longer be trusted
// cause the adapter to close the connection and release all
// resources, at which point it is ready for Open to be called
// again.
typedef enum TLSIO_STATE_TAG
{
    TLSIO_STATE_NOT_OPEN,
    TLSIO_STATE_OPEN,
} TLSIO_STATE;

// This structure definition is mirrored in the unit tests, so if you change
// this struct, keep it in sync with the one in tlsio_openssl_compact_ut.c
typedef struct TLS_IO_INSTANCE_TAG
{
    uint16_t struct_size;
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_ERROR on_io_error;
    void* on_bytes_received_context;
    void* on_io_error_context;
    SSL* ssl;
    SSL_CTX* ssl_context;
    TLSIO_STATE tlsio_state;
    uint32_t host_address;
    int port;
    char* certificate;
    const char* x509certificate;
    const char* x509privatekey;
    int sock;
} TLS_IO_INSTANCE;

// Non-null options are okay; we don't delete them after a close because
// the set options calls are conceptually part of create. 
// Positive option behavior is not yet spec'd, and will get spec'd when x509
// functionality is added.
static void ASSERT_TLSIO_NOT_OPEN(CONCRETE_IO_HANDLE tlsio)
{
    TLS_IO_INSTANCE* tlsio_instance = (TLS_IO_INSTANCE*)tlsio;
    // Assure ourselves that the struct defs are in sync
    ASSERT_ARE_EQUAL_WITH_MSG(uint16_t, sizeof(TLS_IO_INSTANCE), tlsio_instance->struct_size, "bad tlsio struct size");
    ASSERT_ARE_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->on_bytes_received, "on_bytes_received should be NULL");
    ASSERT_ARE_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->on_io_error, "on_io_error should be NULL");
    ASSERT_ARE_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->on_bytes_received_context, "on_bytes_received_context should be NULL");
    ASSERT_ARE_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->on_io_error_context, "on_io_error_context should be NULL");
    ASSERT_ARE_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->ssl, "ssl should be NULL");
    ASSERT_ARE_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->ssl_context, "ssl_context should be NULL");
    ASSERT_ARE_EQUAL_WITH_MSG(int, TLSIO_STATE_NOT_OPEN, (int)tlsio_instance->tlsio_state, "tlsio_state should be TLSIO_STATE_NOT_OPEN");
    ASSERT_ARE_EQUAL_WITH_MSG(int, SSL_goood_port_number, (int)tlsio_instance->port, "port should be SSL_goood_port_number");
    //ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->certificate);
    //ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->x509certificate);
    //ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->x509privatekey);
    ASSERT_ARE_EQUAL_WITH_MSG(int, SSL_SOCKET_NULL_SOCKET, (int)tlsio_instance->sock, "sock should be SSL_SOCKET_NULL_SOCKET");
}

static void ASSERT_TLSIO_NEWLY_CREATED(CONCRETE_IO_HANDLE tlsio)
{
    TLS_IO_INSTANCE* tlsio_instance = (TLS_IO_INSTANCE*)tlsio;
    ASSERT_TLSIO_NOT_OPEN(tlsio_instance);
    ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->certificate);
    ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->x509certificate);
    ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->x509privatekey);
}

static void ASSERT_TLSIO_OPEN(CONCRETE_IO_HANDLE tlsio)
{
    TLS_IO_INSTANCE* tlsio_instance = (TLS_IO_INSTANCE*)tlsio;
    // Assure ourselves that the struct defs are in sync
    ASSERT_ARE_EQUAL_WITH_MSG(uint16_t, sizeof(TLS_IO_INSTANCE), tlsio_instance->struct_size, "bad tlsio struct size");
    ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->on_bytes_received, "on_bytes_received should not be NULL");
    ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->on_io_error, "on_io_error should not be NULL");
    //ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->on_bytes_received_context);
    //ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->on_io_error_context);
    ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->ssl, "ssl should not be NULL");
    ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, 0, (int)tlsio_instance->ssl_context, "ssl_context should not be NULL");
    ASSERT_ARE_EQUAL_WITH_MSG(int, TLSIO_STATE_OPEN, (int)tlsio_instance->tlsio_state, "ssl_context should be TLSIO_STATE_OPEN");
    ASSERT_ARE_EQUAL_WITH_MSG(int, SSL_goood_port_number, (int)tlsio_instance->port, "port should be SSL_goood_port_number");
    //ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->certificate);
    //ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->x509certificate);
    //ASSERT_ARE_EQUAL(int, 0, (int)tlsio_instance->x509privatekey);
    ASSERT_ARE_NOT_EQUAL_WITH_MSG(int, SSL_SOCKET_NULL_SOCKET, (int)tlsio_instance->sock, "sock should not be SSL_SOCKET_NULL_SOCKET");
}
