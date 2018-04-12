
#include <stdint.h>
#include <string.h>
#include <ctime>
#include <algorithm>
#include <random>
#include <functional>
#include <boost/endian/arithmetic.hpp>
#include <boost/format.hpp>

#include <common_utils/common.h>

#include "obfs_utils/http.h"

static auto kHttpRequestTemplate = boost::format(
    "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "User-Agent: curl/7.%d.%d\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "Content-Length: %zu\r\n"
    "\r\n"
);

static auto kHttpResponseTemplate = boost::format(
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Server: nginx/1.%d.%d\r\n"
    "Date: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n"
    "\r\n"
);

static std::default_random_engine kEngine{ std::random_device{}() };

static void RandB64(char *buf, size_t len);
static ssize_t CheckHeader(Buffer &buf);
static ssize_t GetHeader(const char *header, const char *data, size_t len, std::string &value);

ssize_t HttpObfs::ObfsRequest(Buffer &buf) {
    if (obfs_stage_) {
        return buf.Size();
    }
    obfs_stage_ = 1;

    static int kMajorVersion = kEngine() % 51;
    static int kMinorVersion = kEngine() % 2;

    std::string host_port = hostname_.to_string();
    if (kArgs->obfs_port != 80) {
        host_port.push_back(':');
        host_port += std::to_string(kArgs->obfs_port);
    }

    char b64[24];
    RandB64(b64, sizeof b64);

    kHttpRequestTemplate % kArgs->obfs_uri % host_port
                         % kMajorVersion % kMinorVersion
                         % b64 % buf.Size();
    auto obfs_buf = boost::str(kHttpRequestTemplate);
    size_t buf_len = buf.Size();
    buf.Append(obfs_buf.size());
    std::copy_backward(buf.Begin(), buf.Begin() + buf_len, buf.End());
    std::copy(obfs_buf.begin(), obfs_buf.end(), buf.Begin());

    return buf.Size();
}

ssize_t HttpObfs::DeObfsResponse(Buffer &buf) {
    return DeObfsHeader(buf);
}

ssize_t HttpObfs::ObfsResponse(Buffer &buf) {
    if (obfs_stage_) {
        return buf.Size();
    }
    obfs_stage_ = 1;

    static int kMajorVersion = kEngine() % 11;
    static int kMinorVersion = kEngine() % 12;

    char datetime[64];
    char b64[24];

    std::time_t now;
    std::tm *tm_now;

    std::time(&now);
    tm_now = std::localtime(&now);
    std::strftime(datetime, sizeof datetime, "%a, %d %b %Y %H:%M:%S GMT", tm_now);

    RandB64(b64, sizeof b64);

    kHttpResponseTemplate % kMajorVersion % kMinorVersion % datetime % b64;
    auto obfs_buf = boost::str(kHttpResponseTemplate);
    size_t buf_len = buf.Size();
    buf.Append(obfs_buf.size());
    std::copy_backward(buf.Begin(), buf.Begin() + buf_len, buf.End());
    std::copy(obfs_buf.begin(), obfs_buf.end(), buf.Begin());

    return buf.Size();
}

ssize_t HttpObfs::DeObfsRequest(Buffer &buf) {
    return DeObfsHeader(buf);
}

ssize_t HttpObfs::DeObfsHeader(Buffer &buf) {
    if (deobfs_stage_) {
        return buf.Size();
    }
    ssize_t check_result = CheckHeader(buf);
    if (check_result <= 0) { return check_result; }
    deobfs_stage_ = 1;

    char *data = (char *)buf.GetData();
    ssize_t len = buf.Size();
    size_t unused_length = 0;

    while (len >= 4) {
        if (data[0] == '\r' && data[1] == '\n'
            && data[2] == '\r' && data[3] == '\n') {
            len  -= 4;
            data += 4;
            unused_length += 4;
            break;
        }
        len--;
        data++;
        unused_length++;
    }

    if (unused_length) {
        buf.DeQueue(unused_length);
    }
    return unused_length ? buf.Size() : 0;
}

ssize_t CheckHeader(Buffer &buf) {
    char *data = (char *)buf.GetData();
    ssize_t len = buf.Size();

    if (len < 4) { return 0; }

    if (strncasecmp(data, "GET", 3) != 0) {
        return -1;
    }

    {
        std::string protocol;
        ssize_t result = GetHeader("Upgrade:", data, len, protocol);
        if (result <= 0) {
            return result;
        }
        if (strncmp(protocol.c_str(), "websocket", result) != 0) {
            return -1;
        }
    }

    return buf.Size();
}

void RandB64(char *buf, size_t len) {
    static const char kB64Chars[] = \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static std::uniform_int_distribution<> u{ 0, (sizeof kB64Chars) - 1 };

    auto last = std::generate_n(buf, len - 2, [&]() { return kB64Chars[u(kEngine)]; });
    if (kEngine() % 2) {
        *last++ = '=';
        *last = '=';
        return;
    }
    *last++ = kB64Chars[u(kEngine)];
    if (kEngine() % 2) {
        *last = '=';
        return;
    }
    *last = kB64Chars[u(kEngine)];
}

ssize_t NextHeader(const char **data, size_t *len) {
    ssize_t header_len;

    while (*len > 2 && (*data)[0] != '\r' && (*data)[1] != '\n') {
        (*len)--;
        (*data)++;
    }

    *data += 2;
    *len  -= 2;

    header_len = 0;
    while (*len > header_len + 1
           && (*data)[header_len] != '\r'
           && (*data)[header_len + 1] != '\n') {
        header_len++;
    }

    return header_len;

}

ssize_t GetHeader(const char *header, const char *data, size_t data_len, std::string &value) {
    ssize_t len, header_len;

    header_len = strlen(header);

    while ((len = NextHeader(&data, &data_len)) != 0) {
        if (len > header_len && strncasecmp(header, data, header_len) == 0) {
            while (header_len < len && isblank((uint8_t)data[header_len])) {
                header_len++;
            }

            value.append(data + header_len, len - header_len);

            return value.size();
        }
    }

    if (data_len == 0) {
        return 0;
    }

    return -1;
}

static const ObfsGeneratorRegister<HttpObfs> kReg("http");

