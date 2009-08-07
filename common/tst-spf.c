#include "spf.h"
#include "server.h"


int main(int argc, char *argv[])
{
    if (argc < 2) {
        return -1;
    }
    spf_check(NULL, argv[1], NULL);
    return server_loop(NULL, NULL, NULL, NULL, NULL);
}

/* vim:set et sw=4 sts=4 sws=4: */
