#ifndef __SERVER_H__
#define __SERVER_H__

#include <boost/asio.hpp>

#include <protocol_hooks/basic_protocol.h>
#include <protocol_hooks/basic_stream_server.h>

class Session;

DECLARE_STREAM_SERVER(ForwardServer, Session);

#endif

