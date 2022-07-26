
#ifndef _LIBCAP_DEBUG_H
#define _LIBCAP_DEBUG_H


#define DEBUG false

#if DEBUG
#define DBG(str, ...) printf(str, ##__VA_ARGS__)
#else
#define DBG(str, ...)
#endif


#endif /* _LIBCAP_DEBUG_H */
