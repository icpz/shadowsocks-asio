#include <iostream>
#include <fstream>
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include <protocol_plugins/shadowsocks.h>
#include <crypto_utils/aead.h>
#include <crypto_utils/crypto.h>

#include "server.h"

void InitialLogLevel(int verbose);

int main(int argc, char *argv[]) {

    namespace bpo = boost::program_options;

    bpo::options_description desc("Socks5 Proxy Server");
    desc.add_options()
        ("bind-port,l", bpo::value<uint16_t>()->default_value(58888), "Specific port that server will listen")
        ("server-address,s", bpo::value<std::string>(), "Server address")
        ("server-port,p", bpo::value<uint16_t>()->default_value(8088), "Server port")
        ("method,m", bpo::value<std::string>(), "Cipher method")
        ("password,k", bpo::value<std::string>(), "Password")
        ("config-file,c", bpo::value<std::string>(), "Configuration file")
        ("verbose,v", bpo::value<int>()->default_value(1),"Verbose log")
        ("help,h", "Print this help message");

    bpo::variables_map vm;
    bpo::store(bpo::parse_command_line(argc, argv, desc), vm);
    bpo::notify(vm);
    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    if (vm.count("config-file")) {
        auto filename = vm["config-file"].as<std::string>();
        std::ifstream ifs(filename);
        if (!ifs) {
            std::cerr << "Unavailable configure file" << std::endl;
            return -1;
        }
        bpo::store(bpo::parse_config_file(ifs, desc), vm);
        bpo::notify(vm);
    }
    
    uint16_t bind_port = vm["bind-port"].as<uint16_t>();
    if (!vm.count("server-address")) {
        std::cerr << "Please specify the server address" << std::endl;
        return -1;
    }
    auto server_address = boost::asio::ip::make_address(vm["server-address"].as<std::string>());
    if (server_address.is_unspecified()) {
        std::cerr << "Unavailable server address" << std::endl;
        return -1;
    }
    uint16_t server_port = vm["server-port"].as<uint16_t>();

    if (!vm.count("password")) {
        std::cerr << "Please specify the password" << std::endl;
        return -1;
    }
    std::string password = vm["password"].as<std::string>();

    InitialLogLevel(vm["verbose"].as<int>());
    boost::asio::io_context ctx;

    if (!vm.count("method")) {
        std::cerr << "Please specify a cipher method using -m option" << std::endl;
        return -1;
    }
    auto factory = CryptoContextGeneratorFactory::Instance();
    auto CryptoGenerator = factory->GetGenerator(vm["method"].as<std::string>(), password);
    if (!CryptoGenerator) {
        std::cerr << "Invalid cipher type!" << std::endl;
        return -1;
    }
    boost::asio::ip::tcp::endpoint ep(server_address, server_port);
    auto ProtocolGenerator = [ep, g = std::move(CryptoGenerator)]() {
        return GetProtocol<ShadowsocksProtocol>(ep, *g);
    };
    Socks5ProxyServer server(
        ctx, bind_port, ProtocolGenerator
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

void InitialLogLevel(int verbose) {
    boost::log::trivial::severity_level level;
    verbose = std::min(3, verbose);
    switch(verbose) {
    case 3:
        level = boost::log::trivial::trace;
        break;
    case 2:
        level = boost::log::trivial::debug;
        break;
    case 1:
        level = boost::log::trivial::info;
        break;
    default:
        level = boost::log::trivial::warning;
        break;
    }
    boost::log::core::get()->set_filter
    (
        boost::log::trivial::severity >= level
    );
}
