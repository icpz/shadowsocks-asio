
#include <stdlib.h>

#include "common_utils/common.h"

void InitialLogLevel(const char *argv0, int verbose) {
    if (verbose > 0) {
        FLAGS_v = verbose;
    } else {
        FLAGS_minloglevel = -verbose;
    }
    FLAGS_logtostderr = 1;
    FLAGS_colorlogtostderr = 1;
    google::InitGoogleLogging(argv0);
}

