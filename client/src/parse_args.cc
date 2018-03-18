#include <cstdlib>
#include <fstream>
#include <iostream>
#include <boost/program_options.hpp>

#include <crypto_utils/crypto.h>
#include <protocol_plugins/shadowsocks.h>

#include "parse_args.h"

namespace bpo = boost::program_options;

auto ParseArgs(int argc, char *argv[], uint16_t *bind_port, int *log_level)
    -> std::function<std::unique_ptr<BasicProtocol>(void)> {
    auto factory = CryptoContextGeneratorFactory::Instance();
    bpo::options_description desc("Socks5 Proxy Server");
    desc.add_options()
        ("bind-port,l", bpo::value<uint16_t>()->default_value(58888),
            "Specific port that server will listen")
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
        std::vector<std::string> methods;
        factory->GetAllRegisteredNames(methods);
        std::cout << "Available methods:\n   ";
        for (auto &m : methods) {
            std::cout << " " << m;
        }
        std::cout << std::endl;
        exit(0);
    }

    if (vm.count("config-file")) {
        auto filename = vm["config-file"].as<std::string>();
        std::ifstream ifs(filename);
        if (!ifs) {
            std::cerr << "Unavailable configure file" << std::endl;
            exit(-1);
        }
        bpo::store(bpo::parse_config_file(ifs, desc), vm);
        bpo::notify(vm);
    }
    
    *bind_port = vm["bind-port"].as<uint16_t>();
    if (!vm.count("server-address")) {
        std::cerr << "Please specify the server address" << std::endl;
        exit(-1);
    }
    std::string server_host = vm["server-address"].as<std::string>();
    boost::system::error_code ec;
    auto server_address = boost::asio::ip::make_address(server_host, ec);
    bool server_need_resolve = false;
    if (ec) {
        server_need_resolve = true;
    }
    uint16_t server_port = vm["server-port"].as<uint16_t>();

    if (!vm.count("password")) {
        std::cerr << "Please specify the password" << std::endl;
        exit(-1);
    }
    std::string password = vm["password"].as<std::string>();

    *log_level = vm["verbose"].as<int>();

    if (!vm.count("method")) {
        std::cerr << "Please specify a cipher method using -m option" << std::endl;
        exit(-1);
    }
    auto CryptoGenerator = factory->GetGenerator(vm["method"].as<std::string>(), password);
    if (!CryptoGenerator) {
        std::cerr << "Invalid cipher type!" << std::endl;
        exit(-1);
    }
    if (!server_need_resolve) {
        boost::asio::ip::tcp::endpoint ep(server_address, server_port);
        return  [ep, g = std::move(CryptoGenerator)]() {
                    return GetProtocol<ShadowsocksProtocol>(ep, *g);
                };
    }
    return [s = std::move(server_host),
            p = server_port,
            g = std::move(CryptoGenerator)]() {
               return GetProtocol<ShadowsocksProtocol>(s, p, *g);
           };
}

