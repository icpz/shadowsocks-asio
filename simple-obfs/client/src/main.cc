
#include <stdlib.h>
#include <glog/logging.h>

#include <obfs_utils/obfs_proto.h>

#include "server.h"
#include "parse_args.h"

int main(int argc, char *argv[]) {
    int log_level;
    StreamServerArgs args;
    ResolverArgs rargs;

    ParseArgs(argc, argv, &args, &rargs, &log_level);

    InitialLogLevel(argv[0], log_level);

    boost::asio::io_context ctx;

    auto resolver = std::make_shared<cares::tcp::resolver>(ctx);
    boost::system::error_code ec;
    if (!rargs.servers.empty()) {
        resolver->set_servers(rargs.servers, ec);
        if (ec) {
            throw ec;
        }
    }
    if (!rargs.mode.empty()) {
        resolver->resolve_mode(rargs.mode, ec);
        if (ec) {
            throw ec;
        }
    }

    auto server = std::make_shared<ForwardServer>(ctx, args, std::move(resolver));

    boost::asio::signal_set signals(ctx, SIGINT, SIGTERM);

    signals.async_wait(
        [&server](boost::system::error_code ec, int sig) {
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }
            LOG(INFO) << "Signal: " << sig << " received";
            if (server && !server->Stopped()) {
                server->Stop();
            }
        }
    );

    ctx.run();

    google::ShutDownCommandLineFlags();

    return 0;
}

