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

    std::unique_ptr<ForwardServer> tcp_server;
    std::unique_ptr<UdpRelayServer> udp_server;
    std::unique_ptr<boost::process::child> plugin_process;

    if (udp_param.udp_only || udp_param.udp_enable) {
        udp_server.reset(
            new UdpRelayServer(ctx, udp_param.bind_ep,
                               std::move(udp_param.crypto))
        );
    }

    if (!udp_param.udp_only) {
        tcp_server.reset(new ForwardServer(ctx, args.bind_ep, args.generator, args.timeout));

        std::thread([&plugin_process, &plugin, &main_ctx(ctx), &tcp_server, &udp_server]() {
            boost::asio::io_context ctx;
            plugin_process = StartPlugin(ctx, plugin,
                [&main_ctx, &tcp_server, &udp_server]() {
                    boost::asio::post(
                        main_ctx,
                        [&udp_server, &tcp_server, &main_ctx]() {
                            if (tcp_server && !tcp_server->Stopped()) {
                                LOG(ERROR) << "tcp server will terminate due to plugin exited";
                                tcp_server->Stop();
                            }
                            if (udp_server && !udp_server->Stopped()) {
                                LOG(ERROR) << "udp server will terminate due to plugin exited";
                                udp_server->Stop();
                            }
                            main_ctx.stop();
                        }
                    );
                }
            );
            ctx.run();
        }).detach();
    }

    boost::asio::signal_set signals(ctx, SIGINT, SIGTERM);

    signals.async_wait(
        [&tcp_server, &udp_server, &plugin_process]
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
            if (plugin_process && plugin_process->running()) {
                plugin_process->terminate();
            }
        }
    );

    ctx.run();

    if (plugin_process && plugin_process->running()) {
        plugin_process->terminate();
    }

    return 0;
}

