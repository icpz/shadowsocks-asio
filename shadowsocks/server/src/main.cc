#include <boost/asio.hpp>

#include <common_utils/common.h>
#include <crypto_utils/crypto.h>

#include "server.h"
#include "udprelay.h"
#include "parse_args.h"

int main(int argc, char *argv[]) {
    int log_level;
    Plugin plugin;
    StreamServerArgs args;
    UdpServerParam udp_param;

    ParseArgs(argc, argv, &args, &log_level, &plugin, &udp_param);

    InitialLogLevel(argv[0], log_level);

    boost::asio::io_context ctx;

    std::shared_ptr<ForwardServer> tcp_server;
    std::shared_ptr<UdpRelayServer> udp_server;
    std::unique_ptr<boost::process::child> plugin_process;

    if (udp_param.udp_only || udp_param.udp_enable) {
        udp_server.reset(
            new UdpRelayServer(ctx, udp_param.bind_ep,
                               std::move(udp_param.crypto))
        );
    }

    boost::asio::signal_set signals(ctx, SIGINT, SIGTERM);

    if (!udp_param.udp_only) {
        tcp_server.reset(new ForwardServer(ctx, args.bind_ep, args.generator, args.timeout));

        plugin_process = StartPlugin(plugin,
            [&ctx, &tcp_server, &udp_server, &signals]() {
                boost::asio::post(
                    ctx,
                    [&udp_server, &tcp_server, &signals]() {
                        bool need_cancel_signal = false;
                        if (tcp_server && !tcp_server->Stopped()) {
                            LOG(ERROR) << "tcp server will terminate due to plugin exited";
                            tcp_server->Stop();
                            need_cancel_signal = true;
                        }
                        if (udp_server && !udp_server->Stopped()) {
                            LOG(ERROR) << "udp server will terminate due to plugin exited";
                            udp_server->Stop();
                            need_cancel_signal = true;
                        }
                        if (need_cancel_signal) {
                            signals.cancel();
                        }
                    }
                );
            }
        );
    }

    signals.async_wait(
        [&tcp_server, &udp_server]
        (boost::system::error_code ec, int sig) {
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }
            LOG(INFO) << "Signal: " << sig << " received";
            if (tcp_server && !tcp_server->Stopped()) {
                tcp_server->Stop();
            }
            if (udp_server && !udp_server->Stopped()) {
                udp_server->Stop();
            }
        }
    );

    ctx.run();

    if (plugin_process && plugin_process->running()) {
        plugin_process->terminate();
    }

    return 0;
}

