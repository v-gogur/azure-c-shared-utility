#define SETOPTION_PV_COUNT 3
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
