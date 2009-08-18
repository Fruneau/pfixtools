#include "spf.h"
#include "server.h"

static void spf_done(spf_code_t code, const char* explanation, void* data)
{
    const char* str = "";
    switch (code) {
      case SPF_NONE: str = "NONE"; break;
      case SPF_NEUTRAL: str = "NEUTRAL"; break;
      case SPF_PASS: str = "PASS"; break;
      case SPF_FAIL: str = "FAIL"; break;
      case SPF_SOFTFAIL: str = "SOFTFAIL"; break;
      case SPF_TEMPERROR: str = "TEMPERROR"; break;
      case SPF_PERMERROR: str = "PERMERROR"; break;
    }
    info("SPF result: %s with %s", str, explanation != NULL ? explanation : "(no explanation)");
    exit(0);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        return -1;
    }
    spf_check(argv[2], argv[1], NULL, spf_done, true, NULL);
    return server_loop(NULL, NULL, NULL, NULL, NULL);
}

/* vim:set et sw=4 sts=4 sws=4: */
