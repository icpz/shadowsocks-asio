#ifndef __PARSE_ARGS_H__
#define __PARSE_ARGS_H__

#include <functional>
#include <boost/asio.hpp>

#include <protocol_hooks/basic_protocol.h>
#include <protocol_hooks/basic_stream_server.h>

void ParseArgs(int argc, char *argv[], StreamServerArgs *args, int *log_level, std::string *dns);

#endif

