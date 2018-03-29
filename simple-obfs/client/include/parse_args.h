#ifndef __PARSE_ARGS_H__
#define __PARSE_ARGS_H__

#include <functional>
#include <boost/asio.hpp>

#include <protocol_hooks/basic_protocol.h>

auto ParseArgs(int argc, char *argv[], boost::asio::ip::tcp::endpoint *ep, int *log_level)
        -> std::function<std::unique_ptr<BasicProtocol>(void)>;

#endif

