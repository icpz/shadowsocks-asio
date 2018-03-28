
#include <stdlib.h>
#include <glog/logging.h>

#include <obfs_utils/obfs_proto.h>
#include <obfs_utils/tls.h>

#include "server.h"
#include "parse_args.h"

int main(int argc, char *argv[]) {
    uint16_t bind_port;
    int log_level;

    auto ProtocolGenerator = ParseArgs(argc, argv, &bind_port, &log_level);

    InitialLogLevel(argv[0], log_level);

    boost::asio::io_context ctx;

    ForwardServer server(ctx, bind_port, ProtocolGenerator);

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

