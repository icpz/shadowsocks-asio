#include <boost/asio.hpp>

#include <common_utils/common.h>
#include <plugin_utils/plugin.h>

#include "server.h"
#include "parse_args.h"

int main(int argc, char *argv[]) {
    int log_level;
    Plugin plugin;
    StreamServerArgs args;

    ParseArgs(argc, argv, &log_level, &args, &plugin);

    InitialLogLevel(argv[0], log_level);

    boost::asio::io_context ctx;

    std::shared_ptr<Socks5ProxyServer> tcp_server;

    tcp_server.reset(new Socks5ProxyServer(ctx, args.bind_ep, args.generator, args.timeout));

    boost::asio::signal_set signals(ctx, SIGINT, SIGTERM);

    std::unique_ptr<boost::process::child> plugin_process;
    plugin_process = StartPlugin(plugin,
        [&ctx, &tcp_server, &signals]() {
            boost::asio::post(
                ctx,
                [&tcp_server, &signals]() {
                    bool need_cancel_signal = false;
                    if (tcp_server && !tcp_server->Stopped()) {
                        LOG(ERROR) << "server will terminate due to plugin exited";
                        tcp_server->Stop();
                        need_cancel_signal = true;
                    }
                    if (need_cancel_signal) {
                        signals.cancel();
                    }
                }
            );
        }
    );

    signals.async_wait(
        [&tcp_server](boost::system::error_code ec, int sig) {
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }
            LOG(INFO) << "Signal: " << sig << " received";
            if (tcp_server && !tcp_server->Stopped()) {
                tcp_server->Stop();
            }
        }
    );

    ctx.run();

    if (plugin_process && plugin_process->running()) {
        plugin_process->terminate();
    }

    return 0;
}

