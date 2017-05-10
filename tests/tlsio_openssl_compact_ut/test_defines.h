#define OPEN_PV_COUNT 4
typedef struct
{
    TLSIO_CONFIG* config;
    const char* fail_msg;
} create_parameters_t;

void populate_create_parameters(create_parameters_t* p, TLSIO_CONFIG* config, const char* hostname, int port, const char* fail_msg)
{
    p->config = config;
    if (config != NULL)
    {
        config->hostname = hostname;
        config->port = port;
        config->underlying_io_interface = NULL;
        config->underlying_io_parameters = NULL;
    }
    p->fail_msg = fail_msg;
}

typedef struct
{
    CONCRETE_IO_HANDLE tlsio;
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_ERROR on_io_error;
    const char* fail_msg;
} open_parameters_t;

void populate_open_parameters(open_parameters_t* p, CONCRETE_IO_HANDLE tlsio, ON_IO_OPEN_COMPLETE on_io_open_complete,
    ON_BYTES_RECEIVED on_bytes_received, ON_IO_ERROR on_io_error, const char* fail_msg)
{
    p->tlsio = tlsio;
    p->on_io_open_complete = on_io_open_complete;
    p->on_bytes_received = on_bytes_received;
    p->on_io_error = on_io_error;
    p->fail_msg = fail_msg;
}
