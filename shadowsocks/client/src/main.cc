#include <boost/asio.hpp>

#include <common_utils/common.h>
#include <plugin_utils/plugin.h>

#include "server.h"
#include "parse_args.h"

void SignalHandler(boost::asio::signal_set &signals,
                   std::shared_ptr<Socks5ProxyServer> tcp,
                   boost::system::error_code ec, int sig);

int main(int argc, char *argv[]) {
    int log_level;
    Plugin plugin;
    StreamServerArgs args;

    ParseArgs(argc, argv, &log_level, &args, &plugin);

    InitialLogLevel(argv[0], log_level);

    boost::asio::io_context ctx;

    std::shared_ptr<Socks5ProxyServer> tcp_server;

    tcp_server.reset(new Socks5ProxyServer(ctx, args));

    boost::asio::signal_set signals(ctx, SIGINT, SIGTERM);

#ifndef WINDOWS
    signals.add(SIGINFO);
#endif

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
        std::bind(
            SignalHandler,
            std::ref(signals),
            tcp_server,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );

    ctx.run();

    if (plugin_process && plugin_process->running()) {
        plugin_process->terminate();
    }

    google::ShutDownCommandLineFlags();

    return 0;
}

void SignalHandler(boost::asio::signal_set &signals,
                   std::shared_ptr<Socks5ProxyServer> tcp,
                   boost::system::error_code ec, int sig) {
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }
    LOG(INFO) << "Signal: " << sig << " received";

#ifndef WINDOWS
    if (sig == SIGINFO) {
        boost::asio::post(
            signals.get_executor().context(),
            [tcp]() {
                tcp->DumpConnections();
            }
        );
        signals.async_wait(
            std::bind(
                SignalHandler,
                std::ref(signals), tcp,
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }
#endif

    if (tcp && !tcp->Stopped()) {
        tcp->Stop();
    }
}

