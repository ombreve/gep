#ifndef CONFIG_H
#define CONFIG_H

#ifndef GEP_VERSION
#define GEP_VERSION 1.0
#endif

#ifndef GEP_FILE_EXTENSION
#define GEP_FILE_EXTENSION .gep
#endif

#ifndef GEP_PASSWORD_MAX
#define GEP_PASSWORD_MAX 64
#endif

#ifndef GEP_KEY_ITERATIONS
#define GEP_KEY_ITERATIONS 25  /* 32MB */
#endif

#ifndef GEP_SECKEY_ITERATIONS
#define GEP_SECKEY_ITERATIONS 29 /* 512MB */
#endif

#ifndef GEP_AGENT_TIMEOUT
#define GEP_AGENT_TIMEOUT 900 /* seconds (15 minutes) */
#endif

#define STR(a) XSTR(a)
#define XSTR(a) #a

#endif /* CONFIG_H */
