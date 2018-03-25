#ifndef __PARSE_ARGS_H__
#define __PARSE_ARGS_H__

#include <functional>

#include <protocol_hooks/basic_protocol.h>
#include <plugin_utils/plugin.h>

auto ParseArgs(int argc, char *argv[], uint16_t *bind_port, int *log_level, Plugin *plugin)
        -> std::function<std::unique_ptr<BasicProtocol>(void)>;

#endif
