#ifndef __PARSE_ARGS_H__
#define __PARSE_ARGS_H__

#include <functional>
#include <boost/asio.hpp>

#include <protocol_hooks/basic_protocol.h>
#include <protocol_hooks/basic_stream_server.h>
#include <common_utils/options.h>

void ParseArgs(int argc, char *argv[], StreamServerArgs *args, ResolverArgs *rargs, int *log_level);

#endif

