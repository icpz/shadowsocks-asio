#include <cstdlib>
#include <iostream>
#include <sstream>
#include <boost/program_options.hpp>

#include <obfs_utils/obfs.h>
#include <obfs_utils/obfs_proto.h>

#include "parse_args.h"

namespace bpo = boost::program_options;
using boost::asio::ip::tcp;

void ParseArgs(int argc, char *argv[], StreamServerArgs *args, int *log_level) {
    auto factory = ObfsGeneratorFactory::Instance();
    Obfuscator::ArgsType obfs_args;
    bpo::options_description desc("Simple Obfs Server");
    desc.add_options()
        ("bind-address,b", bpo::value<std::string>()->default_value("::"), "Bind address")
        ("bind-port,l", bpo::value<uint16_t>(),
            "Specific port that server will listen")
        ("server-address,s", bpo::value<std::string>(), "Server address")
        ("server-port,p", bpo::value<uint16_t>(), "Server port")
        ("obfs", bpo::value<std::string>(), "Obfuscate mode")
        ("obfs-host", bpo::value<std::string>()->default_value(""), "Obfuscate hostname")
        ("obfs-forward", bpo::value<std::string>(), "Obfuscator forward option")
        ("verbose", bpo::value<int>()->default_value(1),"Verbose log")
        ("timeout", bpo::value<size_t>()->default_value(60), "Timeout in seconds")
        ("help,h", "Print this help message");

    bpo::variables_map vm;
    bpo::store(bpo::parse_command_line(argc, argv, desc), vm);
    bpo::notify(vm);
    if (vm.count("help")) {
        std::cout << desc << std::endl;
        std::vector<std::string> modes;
        factory->GetAllRegisteredNames(modes);
        std::cout << "Available obfs modes:\n   ";
        for (auto &m : modes) {
            std::cout << " " << m;
        }
        std::cout << std::endl;
        exit(0);
    }

    bool plugin_mode = false;
    char *opts_from_env = getenv("SS_PLUGIN_OPTIONS");
    if (opts_from_env) {
        std::string opts = opts_from_env;
        std::replace(opts.begin(), opts.end(), ';', '\n');
        std::istringstream iss(opts);

        bpo::store(bpo::parse_config_file(iss, desc), vm);
        bpo::notify(vm);
        plugin_mode = true;
    }

    *log_level = vm["verbose"].as<int>();

    if (!vm.count("obfs") || !vm.count("obfs-host")) {
        std::cerr << "Please specify obfs options using --obfs & --obfs-host options"
                  << std::endl;
        exit(-1);
    }

    obfs_args.obfs_host = vm["obfs-host"].as<std::string>();

    auto obfs_generator = factory->GetGenerator(vm["obfs"].as<std::string>());
    if (!obfs_generator) {
        std::cerr << "Invalid obfs mode!" << std::endl;
        exit(-1);
    }

    std::string server_host;
    uint16_t server_port;
    boost::asio::ip::address bind_address;
    uint16_t bind_port;
    if (plugin_mode) {
        char *opt_from_env;
        if (!(opt_from_env = getenv("SS_REMOTE_HOST"))) {
            exit(-1);
        }
        bind_address = boost::asio::ip::make_address(opt_from_env);

        if (!(opt_from_env = getenv("SS_REMOTE_PORT"))) {
            exit(-1);
        }
        bind_port = (uint16_t)std::stoul(opt_from_env);

        if (!(opt_from_env = getenv("SS_LOCAL_HOST"))) {
            exit(-1);
        }
        server_host = opt_from_env;

        if (!(opt_from_env = getenv("SS_LOCAL_PORT"))) {
            exit(-1);
        }
        server_port = (uint16_t)std::stoul(opt_from_env);
    } else {
        boost::system::error_code ec;
        bind_address = boost::asio::ip::make_address(vm["bind-address"].as<std::string>(), ec);
        if (ec) {
            std::cerr << "Invalid bind address" << std::endl;
            exit(-1);
        }

        if (!vm.count("bind-port")) {
            std::cerr << "Please specify the bind port" << std::endl;
            exit(-1);
        }
        bind_port = vm["bind-port"].as<uint16_t>();

        if (!vm.count("server-address")) {
            std::cerr << "Please specify the server address" << std::endl;
            exit(-1);
        }
        server_host = vm["server-address"].as<std::string>();

        if (!vm.count("server-port")) {
            std::cerr << "Please specify the server port" << std::endl;
            exit(-1);
        }
        server_port = vm["server-port"].as<uint16_t>();
    }

    if (vm.count("obfs-forward")) {
        obfs_args.ParseForwardOpt(vm["obfs-forward"].as<std::string>());
    }
    obfs_args.obfs_port = bind_port;
    Obfuscator::SetObfsArgs(obfs_args);
    args->bind_ep = tcp::endpoint(bind_address, bind_port);
    args->timeout = vm["timeout"].as<size_t>() * 1000;

    auto target_info = std::make_shared<TargetInfo>(MakeTarget(server_host, server_port));
    if (target_info->IsEmpty()) {
        std::cerr << "Invalid server host / port" << std::endl;
        exit(-1);
    }

    args->generator = \
        [target = std::move(target_info), g = *obfs_generator]() {
            return GetProtocol<ObfsServer>(target, g());
        };
    return;
}

