
#include <stdlib.h>
#include <glog/logging.h>

#include <obfs_utils/obfs_proto.h>

#include "server.h"
#include "parse_args.h"

int main(int argc, char *argv[]) {
    int log_level;
    boost::asio::ip::tcp::endpoint ep;

    auto ProtocolGenerator = ParseArgs(argc, argv, &ep, &log_level);

    InitialLogLevel(argv[0], log_level);

    boost::asio::io_context ctx;

    ForwardServer server(ctx, ep, ProtocolGenerator);

    boost::asio::signal_set signals(ctx, SIGINT, SIGTERM);

    signals.async_wait(
        [&server](boost::system::error_code ec, int sig) {
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }
            LOG(INFO) << "Signal: " << sig << " received";
            server.Stop();
        }
    );

    ctx.run();

    return 0;
}

