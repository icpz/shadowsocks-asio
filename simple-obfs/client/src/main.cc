
#include <stdlib.h>
#include <glog/logging.h>

#include <obfs_utils/obfs_proto.h>
#include <obfs_utils/tls.h>

#include "server.h"

int main(int argc, char *argv[]) {

    boost::asio::io_context ctx;
    auto addr = boost::asio::ip::make_address(getenv("SS_REMOTE_HOST"));
    boost::asio::ip::tcp::endpoint ep{ addr, (uint16_t)std::stoul(getenv("SS_REMOTE_PORT")) };
    uint16_t bind_port = std::stoul(getenv("SS_LOCAL_PORT"));

    auto factory = ObfsGeneratorFactory::Instance();
    auto g = factory->GetGenerator("tls", "www.baidu.com");

    ForwardServer server(ctx, bind_port, [ep, g]() {
        return GetProtocol<ObfsClient>(ep, (*g)());
    });

    ctx.run();

    return 0;
}

