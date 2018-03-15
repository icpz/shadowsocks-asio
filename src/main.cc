#include <iostream>
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include "server.h"
#include "basic_protocol.h"

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

    auto protocol_factory = std::make_unique<BasicProtocolFactory>();
    Socks5ProxyServer server(ctx, port, std::move(protocol_factory));

    boost::asio::signal_set signals(ctx, SIGINT, SIGTERM);

    signals.async_wait(
        [&server](boost::system::error_code ec, int sig) {
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }
            LOG(INFO) << "Signal: " << sig << " received";
            server.stop();
        }
    );

    ctx.run();

    return 0;
}

