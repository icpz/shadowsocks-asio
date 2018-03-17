#include <iostream>
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include <protocol_plugins/shadowsocks.h>
#include <crypto_utils/aead.h>

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

    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), 59999);
    using CryptoGeneratorType = std::function<std::unique_ptr<CryptoContext>()>;
    using ProtocolGeneratorType = std::function<std::unique_ptr<BasicProtocol>()>;
    CryptoGeneratorType CryptoGenerator = std::bind(GetCryptoContext<Chacha20Poly1305Ietf, boost::string_view>, "12345678");
    ProtocolGeneratorType ProtocolGenerator = [ep, CryptoGenerator]() { return GetProtocol<ShadowsocksProtocol>(ep, CryptoGenerator); };
    Socks5ProxyServer server(
        ctx, port, ProtocolGenerator
    );

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

