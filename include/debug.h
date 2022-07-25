
#define DEBUG true

#if DEBUG
#define dbg(str, ...) printf(str, ##__VA_ARGS__)
#else
#define dbg(str, ...)
#endif
