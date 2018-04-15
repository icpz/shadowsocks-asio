#ifndef __PARSE_ARGS_H__
#define __PARSE_ARGS_H__

#include <functional>

#include <protocol_hooks/basic_protocol.h>
#include <protocol_hooks/basic_stream_server.h>
#include <plugin_utils/plugin.h>

void ParseArgs(int argc, char *argv[], int *log_level, StreamServerArgs *args, Plugin *plugin);

#endif

