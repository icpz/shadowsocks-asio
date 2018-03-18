#ifndef __COMMON_H__
#define __COMMON_H__

#ifndef LOG
    #include <boost/log/trivial.hpp>
    #define LOG BOOST_LOG_TRIVIAL
    #define TRACE   trace
    #define DEBUG   debug
    #define INFO    info
    #define WARNING warning
    #define ERROR   error
    #define FATAL   fatal

    void InitialLogLevel(int verbose);

#endif // LOG

#endif

