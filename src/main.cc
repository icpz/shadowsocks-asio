#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/asio.hpp>

#include "server.h"

int main(int argc, char *argv[]) {

    boost::log::core::get()->set_filter
    (
        boost::log::trivial::severity >= boost::log::trivial::trace
    );

    boost::asio::io_context ctx;

    Socks5ProxyServer s(ctx, 58888);

    ctx.run();

    return 0;
}

