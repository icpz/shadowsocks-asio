#ifndef __HTTP_H__
#define __HTTP_H__

#include <boost/utility/string_view.hpp>

#include "obfs_utils/obfs.h"

class HttpObfs : public Obfuscator {
public:

    HttpObfs()
        : hostname_(kArgs->obfs_host) {
    }

    ~HttpObfs() { }

    ssize_t ObfsRequest(Buffer &buf);
    ssize_t DeObfsResponse(Buffer &buf);

    ssize_t ObfsResponse(Buffer &buf);
    ssize_t DeObfsRequest(Buffer &buf);
private:
    ssize_t DeObfsHeader(Buffer &buf);

    int obfs_stage_ = 0;
    int deobfs_stage_ = 0;
    boost::string_view hostname_;
};

#endif

