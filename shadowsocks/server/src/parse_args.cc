#include <cstdlib>
#include <fstream>
#include <iostream>
#include <boost/program_options.hpp>

#include <crypto_utils/crypto.h>
#include <ss_proto/shadowsocks.h>

#include "parse_args.h"

namespace bpo = boost::program_options;

auto ParseArgs(int argc, char *argv[], uint16_t *bind_port, int *log_level, Plugin *p)
    -> std::function<std::unique_ptr<BasicProtocol>(void)> {
    auto factory = CryptoContextGeneratorFactory::Instance();
    bpo::options_description desc("Shadowsocks Server");
    desc.add_options()
        ("bind-port,l", bpo::value<uint16_t>()->default_value(58888),
            "Specific port that server will listen")
        ("method,m", bpo::value<std::string>(), "Cipher method")
        ("password,k", bpo::value<std::string>(), "Password")
        ("config-file,c", bpo::value<std::string>(), "Configuration file")
        ("plugin", bpo::value<std::string>(), "Plugin executable name")
        ("plugin-opts", bpo::value<std::string>(), "Plugin options")
        ("verbose", bpo::value<int>()->default_value(1),"Verbose log")
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

    if (!vm.count("password")) {
        std::cerr << "Please specify the password" << std::endl;
        exit(-1);
    }
    std::string password = vm["password"].as<std::string>();

    *log_level = vm["verbose"].as<int>();

    if (vm.count("plugin")) {
        std::string plugin = vm["plugin"].as<std::string>();
        if (!plugin.empty()) {
            p->enable = true;
            p->plugin = plugin;
            p->remote_address = "0.0.0.0";
            p->remote_port = *bind_port;
            p->local_address = "127.0.0.1";
            p->local_port = GetFreePort();
            *bind_port = p->local_port;
            if (*bind_port == 0) {
                std::cerr << "Fatal error: cannot get a freedom port" << std::endl;
                exit(-1);
            }
            if (vm.count("plugin-opts")) {
                p->plugin_options = vm["plugin-opts"].as<std::string>();
            }
        }
    }

    if (!vm.count("method")) {
        std::cerr << "Please specify a cipher method using -m option" << std::endl;
        exit(-1);
    }
    auto CryptoGenerator = factory->GetGenerator(vm["method"].as<std::string>(), password);
    if (!CryptoGenerator) {
        std::cerr << "Invalid cipher type!" << std::endl;
        exit(-1);
    }

    return [g = std::move(CryptoGenerator)]() {
               return GetProtocol<ShadowsocksServer>((*g)());
           };
}

