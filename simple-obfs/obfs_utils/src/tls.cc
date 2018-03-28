
#include <stdint.h>
#include <algorithm>
#include <random>
#include <functional>
#include <boost/endian/arithmetic.hpp>

#include "obfs_utils/tls.h"

using boost::endian::big_to_native;
using boost::endian::native_to_big;

#define CT_HTONS(x) native_to_big<uint16_t>(x)
#define CT_HTONL(x) native_to_big<uint32_t>(x)
#define CT_NTOHS(x) big_to_native<uint16_t>(x)

struct ClientHello {
    uint8_t  content_type;
    uint16_t version;
    uint16_t len;

    uint8_t  handshake_type;
    uint8_t  handshake_len_1;
    uint16_t handshake_len_2;
    uint16_t handshake_version;

    uint32_t random_unix_time;
    uint8_t  random_bytes[28];
    uint8_t  session_id_len;
    uint8_t  session_id[32];
    uint16_t cipher_suites_len;
    uint8_t  cipher_suites[56];
    uint8_t  comp_methods_len;
    uint8_t  comp_methods[1];
    uint16_t ext_len;
} __attribute__((packed, aligned(1)));

struct ExtServerName {
    uint16_t ext_type;
    uint16_t ext_len;
    uint16_t server_name_list_len;
    uint8_t  server_name_type;
    uint16_t server_name_len;
} __attribute__((packed, aligned(1)));

struct ExtSessionTicket {
    uint16_t session_ticket_type;
    uint16_t session_ticket_ext_len;
} __attribute__((packed, aligned(1)));

struct ExtOthers {
    uint16_t ec_point_formats_ext_type;
    uint16_t ec_point_formats_ext_len;
    uint8_t  ec_point_formats_len;
    uint8_t  ec_point_formats[3];

    uint16_t elliptic_curves_type;
    uint16_t elliptic_curves_ext_len;
    uint16_t elliptic_curves_len;
    uint8_t  elliptic_curves[8];

    uint16_t sig_algos_type;
    uint16_t sig_algos_ext_len;
    uint16_t sig_algos_len;
    uint8_t  sig_algos[30];

    uint16_t encrypt_then_mac_type;
    uint16_t encrypt_then_mac_ext_len;

    uint16_t extended_master_secret_type;
    uint16_t extended_master_secret_ext_len;
} __attribute__((packed, aligned(1)));

struct ServerHello {
    uint8_t  content_type;
    uint16_t version;
    uint16_t len;

    uint8_t  handshake_type;
    uint8_t  handshake_len_1;
    uint16_t handshake_len_2;
    uint16_t handshake_version;

    uint32_t random_unix_time;
    uint8_t  random_bytes[28];
    uint8_t  session_id_len;
    uint8_t  session_id[32];
    uint16_t cipher_suite;
    uint8_t  comp_method;
    uint16_t ext_len;

    uint16_t ext_renego_info_type;
    uint16_t ext_renego_info_ext_len;
    uint8_t  ext_renego_info_len;

    uint16_t extended_master_secret_type;
    uint16_t extended_master_secret_ext_len;

    uint16_t ec_point_formats_ext_type;
    uint16_t ec_point_formats_ext_len;
    uint8_t  ec_point_formats_len;
    uint8_t  ec_point_formats[1];
} __attribute__((packed, aligned(1)));

struct ChangeCipherSpec {
    uint8_t  content_type;
    uint16_t version;
    uint16_t len;
    uint8_t  msg;
} __attribute__((packed, aligned(1)));

struct EncryptedHandshake {
    uint8_t  content_type;
    uint16_t version;
    uint16_t len;
} __attribute__((packed, aligned(1)));

static const ClientHello
tls_client_hello_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301),
    .len = 0,

    .handshake_type = 1,
    .handshake_len_1 = 0,
    .handshake_len_2 = 0,
    .handshake_version = CT_HTONS(0x0303),

    .random_unix_time = 0,
    .random_bytes = { 0 },

    .session_id_len = 32,
    .session_id = { 0 },

    .cipher_suites_len = CT_HTONS(56),
    .cipher_suites = {
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
        0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
        0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff
    },

    .comp_methods_len = 1,
    .comp_methods = { 0 },

    .ext_len = 0,
};

static const ExtServerName
tls_ext_server_name_template = {
    .ext_type = 0,
    .ext_len = 0,
    .server_name_list_len = 0,
    .server_name_type = 0,
    .server_name_len = 0,
};

static const ExtSessionTicket
tls_ext_session_ticket_template = {
    .session_ticket_type = CT_HTONS(0x0023),
    .session_ticket_ext_len = 0,
};

static const ExtOthers
tls_ext_others_template = {
    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(4),
    .ec_point_formats_len = 3,
    .ec_point_formats = { 0x01, 0x00, 0x02 },

    .elliptic_curves_type = CT_HTONS(0x000a),
    .elliptic_curves_ext_len = CT_HTONS(10),
    .elliptic_curves_len = CT_HTONS(8),
    .elliptic_curves = { 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18 },

    .sig_algos_type = CT_HTONS(0x000d),
    .sig_algos_ext_len = CT_HTONS(32),
    .sig_algos_len = CT_HTONS(30),
    .sig_algos = {
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
        0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03
    },

    .encrypt_then_mac_type = CT_HTONS(0x0016),
    .encrypt_then_mac_ext_len = 0,

    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,
};

static const ServerHello
tls_server_hello_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0301),
    .len = CT_HTONS(91),

    .handshake_type = 2,
    .handshake_len_1 = 0,
    .handshake_len_2 = CT_HTONS(87),
    .handshake_version = CT_HTONS(0x0303),

    .random_unix_time = 0,
    .random_bytes = { 0 },

    .session_id_len = 32,
    .session_id = { 0 },

    .cipher_suite = CT_HTONS(0xCCA8),
    .comp_method = 0,
    .ext_len = 0,

    .ext_renego_info_type = CT_HTONS(0xFF01),
    .ext_renego_info_ext_len = CT_HTONS(1),
    .ext_renego_info_len = 0,

    .extended_master_secret_type = CT_HTONS(0x0017),
    .extended_master_secret_ext_len = 0,

    .ec_point_formats_ext_type = CT_HTONS(0x000B),
    .ec_point_formats_ext_len = CT_HTONS(2),
    .ec_point_formats_len = 1,
    .ec_point_formats = { 0 },
};

static const ChangeCipherSpec
tls_change_cipher_spec_template = {
    .content_type = 0x14,
    .version = CT_HTONS(0x0303),
    .len = CT_HTONS(1),
    .msg = 0x01,
};

static const EncryptedHandshake
tls_encrypted_handshake_template = {
    .content_type = 0x16,
    .version = CT_HTONS(0x0303),
    .len = 0,
};

const uint8_t tls_data_header[3] = {0x17, 0x03, 0x03};

static void RandBytes(uint8_t *buf, size_t len);
static ssize_t ObfsAppData(Buffer &buf);
static ssize_t DeObfsAppData(Buffer &buf, size_t idx, Frame *frame);

ssize_t TlsObfs::ObfsRequest(Buffer &buf) {
    Buffer tmp;

    if (!obfs_stage_) {

        size_t buf_len = buf.Size();
        size_t hello_len = sizeof(ClientHello);
        size_t server_name_len = sizeof(ExtServerName);
        size_t host_len = hostname_.size();
        size_t ticket_len = sizeof(ExtSessionTicket);
        size_t other_ext_len = sizeof(ExtOthers);
        size_t tls_len = buf_len + hello_len + server_name_len
            + host_len + ticket_len + other_ext_len;

        tmp.AppendData(buf);
        buf.Reset(tls_len);

        /* Client Hello Header */
        ClientHello *hello = (ClientHello *)buf.GetData();
        memcpy(hello, &tls_client_hello_template, hello_len);
        hello->len = CT_HTONS(tls_len - 5);
        hello->handshake_len_2 = CT_HTONS(tls_len - 9);
        hello->random_unix_time = CT_HTONL((uint32_t)time(NULL));
        RandBytes(hello->random_bytes, 28);
        RandBytes(hello->session_id, 32);
        hello->ext_len = CT_HTONS(tls_len - hello_len);

        /* Session Ticket */
        ExtSessionTicket *ticket = (ExtSessionTicket *)((uint8_t *)hello + hello_len);
        memcpy(ticket, &tls_ext_session_ticket_template, ticket_len);
        ticket->session_ticket_ext_len = CT_HTONS(buf_len);
        memcpy((uint8_t *)ticket + ticket_len, tmp.GetData(), buf_len);

        /* SNI */
        ExtServerName *server_name = (ExtServerName *)((uint8_t *)ticket + ticket_len + buf_len);
        memcpy(server_name, &tls_ext_server_name_template, server_name_len);
        server_name->ext_len = CT_HTONS(host_len + 3 + 2);
        server_name->server_name_list_len = CT_HTONS(host_len + 3);
        server_name->server_name_len = CT_HTONS(host_len);
        memcpy((uint8_t *)server_name + server_name_len, hostname_.data(), host_len);

        /* Other Extensions */
        memcpy((uint8_t *)server_name + server_name_len + host_len, &tls_ext_others_template,
                other_ext_len);

        obfs_stage_ = 1;
    } else {
        ObfsAppData(buf);
    }

    return buf.Size();
}

ssize_t TlsObfs::DeObfsResponse(Buffer &buf) {
    if (!deobfs_stage_) {
        VLOG(2) << "initializing deobfs";
        size_t hello_len = sizeof(ServerHello);
        uint8_t *data = buf.GetData();
        ssize_t len    = buf.Size();

        len -= hello_len;
        if (len <= 0) {
            VLOG(2) << "deobfs need more: " << hello_len
                    << ", actually got " << buf.Size();
            return 0; // need more
        }

        ServerHello *hello = (ServerHello *)data;
        if (hello->content_type != tls_server_hello_template.content_type) {
            LOG(WARNING) << "content_type not matching";
            return -1;
        }

        size_t change_cipher_spec_len = sizeof(ChangeCipherSpec);
        size_t encrypted_handshake_len = sizeof(EncryptedHandshake);

        len -= change_cipher_spec_len + encrypted_handshake_len;
        if (len <= 0) {
            VLOG(2) << "dobfs need more";
            return 0; // need more
        }

        size_t tls_len = hello_len + change_cipher_spec_len + encrypted_handshake_len;
        EncryptedHandshake *encrypted_handshake =
            (EncryptedHandshake *)(data + hello_len + change_cipher_spec_len);
        size_t msg_len = CT_NTOHS(encrypted_handshake->len);

        buf.DeQueue(tls_len);

        deobfs_stage_ = 1;

        if (buf.Size() > msg_len) {
            return DeObfsAppData(buf, msg_len, &extra_);
        } else {
            VLOG(2) << "done initialized, dobfs need more";
            extra_.idx = buf.Size() - msg_len;
            if (extra_.idx == 0) {
                return buf.Size();
            }
            VLOG(2) << "extra_.idx: " << extra_.idx;
        }
    } else {
        return DeObfsAppData(buf, 0, &extra_);
    }
    return 0;
}

ssize_t TlsObfs::ObfsResponse(Buffer &buf) {
    return buf.Size();
}

ssize_t TlsObfs::DeObfsRequest(Buffer &buf) {
    return buf.Size();
}

ssize_t ObfsAppData(Buffer &buf) {
    size_t buf_len = buf.Size();

    buf.PrepareCapacity(5);
    std::copy_backward(buf.Begin(), buf.End(), buf.End() + 5);
    buf.Append(5);
    std::copy_n(tls_data_header, 3, buf.Begin());

    uint16_t len = CT_HTONS(buf_len);
    memcpy(buf.GetData() + 3, &len, sizeof len);

    return buf.Size();
}

ssize_t DeObfsAppData(Buffer &buf, size_t idx, Frame *frame) {
    size_t bidx = idx, bofst = idx;
    uint8_t *data = buf.GetData();

    VLOG(3) << "deobfs app data";
    while (bidx < buf.Size()) {
        if (frame->len == 0) {
            if (frame->idx >= 0 && frame->idx < 3
                    && data[bidx] != tls_data_header[frame->idx]) {
                LOG(WARNING) << "invalid frame";
                return -1;
            } else if (frame->idx >= 3 && frame->idx < 5) {
                memcpy(frame->buf + frame->idx - 3, data + bidx, 1);
            } else if (frame->idx < 0) {
                bofst++;
            }
            frame->idx++;
            bidx++;
            if (frame->idx == 5) {
                memcpy(&frame->len, frame->buf, 2);
                boost::endian::big_to_native_inplace(frame->len);
                frame->idx = 0;
            }
            continue;
        }

        if (frame->len > 16384) {
            LOG(WARNING) << "length too big: " << frame->len;
            return -2;
        }

        int left_len = buf.Size() - bidx;

        if (left_len > frame->len) {
            memmove(data + bofst, data + bidx, frame->len);
            bidx  += frame->len;
            bofst += frame->len;
            frame->len = 0;
        } else {
            memmove(data + bofst, data + bidx, left_len);
            bidx  = buf.Size();
            bofst += left_len;
            frame->len -= left_len;
        }
    }

    buf.Reset(bofst);

    return buf.Size();
}

void RandBytes(uint8_t *buf, size_t len) {
    static std::random_device rd;
    static std::uniform_int_distribution<uint16_t> u(0, 255);
    std::generate_n(buf, len, std::bind(std::ref(u), std::ref(rd)));
}

static const ObfsGeneratorRegister<TlsObfs> kReg("tls");

