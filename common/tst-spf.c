#include "spf.h"
#include "server.h"

static void spf_done(spf_code_t code, void* data)
{
    info("SPF result: %d", code);
    exit(0);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        return -1;
    }
    spf_check(NULL, argv[1], NULL, spf_done, NULL);
    return server_loop(NULL, NULL, NULL, NULL, NULL);
}

/* vim:set et sw=4 sts=4 sws=4: */
