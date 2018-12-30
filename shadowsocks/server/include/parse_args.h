#ifndef __PARSE_ARGS_H__
#define __PARSE_ARGS_H__

#include <functional>

#include <protocol_hooks/basic_protocol.h>
#include <protocol_hooks/basic_stream_server.h>
#include <plugin_utils/plugin.h>
#include <common_utils/options.h>

#include "udprelay.h"

void ParseArgs(int argc, char *argv[], StreamServerArgs *args, ResolverArgs *rargs,
               int *log_level, Plugin *plugin, UdpServerParam *udp);

#endif

