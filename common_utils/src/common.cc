
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>

#include "common_utils/common.h"

void InitialLogLevel(int verbose) {
    boost::log::trivial::severity_level level;
    verbose = std::min(3, verbose);
    switch(verbose) {
    case 3:
        level = boost::log::trivial::trace;
        break;
    case 2:
        level = boost::log::trivial::debug;
        break;
    case 1:
        level = boost::log::trivial::info;
        break;
    default:
        level = boost::log::trivial::warning;
        break;
    }
    boost::log::core::get()->set_filter
    (
        boost::log::trivial::severity >= level
    );
}

