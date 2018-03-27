#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef WINDOWS
#define setenv(key, val, ovr) _putenv_s(key, val)
#endif

#include <gflags/gflags.h>
#include <glog/logging.h>

void InitialLogLevel(const char *argv0, int verbose);

#endif

