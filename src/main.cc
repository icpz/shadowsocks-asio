#include <iostream>
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include "server.h"

int main(int argc, char *argv[]) {

    namespace bpo = boost::program_options;

    bpo::options_description desc("Socks5 Proxy Server");
    desc.add_options()
        ("bind-port,p", bpo::value<uint16_t>()->default_value(58888), "Specific port that server will listen")
        ("help", "Print this help message");

    bpo::variables_map vm;
    bpo::store(bpo::parse_command_line(argc, argv, desc), vm);
    bpo::notify(vm);
    
    uint16_t port = vm["bind-port"].as<uint16_t>();
    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    boost::log::core::get()->set_filter
    (
        boost::log::trivial::severity >= boost::log::trivial::trace
    );

    boost::asio::io_context ctx;

    Socks5ProxyServer s(ctx, port);

    ctx.run();

    return 0;
}

