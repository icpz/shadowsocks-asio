#include <boost/asio.hpp>

#include <common_utils/common.h>
#include <protocol_hooks/shadowsocks.h>
#include <crypto_utils/crypto.h>

#include "server.h"

int main(int argc, char *argv[]) {
    boost::asio::io_context ctx;

    auto factory = CryptoContextGeneratorFactory::Instance();

    auto generator = factory->GetGenerator("aes-256-cfb", "12345678");
    ForwardServer server(ctx, 8989, [g = std::move(generator)]() {
        return GetProtocol<ShadowsocksServer>((*g)());
    });

    ctx.run();

    return 0;
}

