#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../config.h"
#include "docs.h"
#include "rfc8439.h"

#define OPTPARSE_IMPLEMENTATION
#include "optparse.h"

#define SHA256_IMPLEMENTATION
#include "sha256.h"

static int agent_timeout = 0;
static char *keyfile = 0;
static const char gep_suffix[] = STR(GEP_FILE_EXTENSION);
static const char gep_aad[] = GEP_ADDITIONAL_AUTHENTIFICATED_DATA;

static char *fatal_oname = 0;
static FILE *fatal_ofd = 0;

/* Print a message and exit the program with a failure code. */
static void
fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "gep: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);

    if (fatal_ofd)
        fclose(fatal_ofd);
    if (fatal_oname)
        remove(fatal_oname);
    exit(EXIT_FAILURE);
}

/* Print a non-fatal warning message. */
static void
warning(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "warning: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* Return a copy of string S, which may be NULL. */
static char *
dupstr(const char *s)
{
    char *copy = 0;

    if (s) {
        size_t len = strlen(s) + 1;
        copy = malloc(len);
        if (!copy)
            fatal("out of memory");
        memcpy(copy, s, len);
    }
    return copy;
}
/* Concatenate N strings as a new string. */
static char *
joinstr(int n, ...)
{
    int i;
    va_list ap;
    char *p, *str;
    size_t len = 1;

    va_start(ap, n);
    for (i = 0; i < n; i++) {
        char *s = va_arg(ap, char *);
        len += strlen(s);
    }
    va_end(ap);

    p = str = malloc(len);
    if (!str)
        fatal("out of memory");

    va_start(ap, n);
    for (i = 0; i < n; i++) {
        char *s = va_arg(ap, char *);
        size_t slen = strlen(s);
        memcpy(p, s, slen);
        p += slen;
    }
    va_end(ap);

    *p = 0;
    return str;
}

/* Get secure entropy suitable for key generation from OS. */
static void
secure_entropy(void *buf, size_t len)
{
    FILE *r = fopen("/dev/urandom", "rb");

    if (!r)
        fatal("failed to open /dev/urandom");
    if (!fread(buf, len, 1, r))
        fatal("failed to gather entropy");
    fclose(r);
}

/* Return non-zero if path exists and is a regular file. */
static int
file_exists(char *path)
{
    struct stat info;

    return !stat(path, &info) && S_ISREG(info.st_mode);
}

/* Return non-zero if path exists and is a directory. */
static int
dir_exists(const char *path)
{
    struct stat info;

    return !stat(path, &info) && S_ISDIR(info.st_mode);
}

/* Prepend $XDG_CONFIG_HOME/gep or $HOME/.config/gep to FILE.
 * Ensure that the directory does exist. */
static char *
storage_directory(char *file)
{
    static const char gep[] = "/gep/";
    static const char config[] = "/.config";
    char *xdg_config_home = getenv("XDG_CONFIG_HOME");
    char *path, *s;

    if (!xdg_config_home) {
        char *home = getenv("HOME");
        if (!home)
            fatal("no $HOME or $XDG_CONFIG_HOME, giving up");
        if (home[0] != '/')
            fatal("$HOME is not absolute");
        path = joinstr(4, home, config, gep, file);
    }
    else {
        if (xdg_config_home[0] != '/')
            fatal("$XDG_CONFIG_HOME is not absolute");
        path = joinstr(3, xdg_config_home, gep, file);
    }

    s = strchr(path + 1, '/');
    while (s) {
        *s = 0;
        if (dir_exists(path) || !mkdir(path, 0700)) {
            DIR *dir = opendir(path);

            if (dir)
                closedir(dir);
            else
                fatal("opendir(%s) -- %s", path, strerror(errno));
        }
        else
            fatal("mkdir(%s) -- %s", path, strerror(errno));
        *s = '/';
        s = strchr(s + 1, '/');
    }
    return path;
}

/* Return the default key file. */
static char *
default_keyfile(void)
{
    return storage_directory("gep.key");
}

/* Fallback method to get a password from terminal. */
static void
get_passdumb(char *buf, char *prompt)
{
    size_t passlen;

    warning("reading key from stdin with echo");
    fputs(prompt, stderr);
    fflush(stderr);
    if (!fgets(buf, GEP_PASSWORD_MAX, stdin))
        fatal("could not read passphrase");
    passlen = strlen(buf);
    if (buf[passlen - 1] < ' ')
        buf[passlen - 1] = 0;
}

/* Read a password from terminal. */
static void
get_pass(char *buf, char *prompt)
{
    int tty;
    char newline = '\n';
    size_t i;
    struct termios old, new;

    tty = open("/dev/tty", O_RDWR);
    if (tty == -1)
        get_passdumb(buf, prompt);
    else {
        if (write(tty, prompt, strlen(prompt)) == -1)
            fatal("error asking for key");
        tcgetattr(tty, &old);
        new = old;
        new.c_lflag &= ~ECHO;
        tcsetattr(tty, TCSANOW, &new);
        errno = 0;
        for (i = 0; i < GEP_PASSWORD_MAX - 1 && read(tty, buf + i, 1) == 1; i++)
            if (buf[i] == '\n' || buf[i] == '\r')
                break;
        buf[i] = 0;
        tcsetattr(tty, TCSANOW, &old);
        if (write(tty, &newline, 1) == -1)
            fatal("error asking for passphrase");
        close(tty);
        if (errno)
            fatal("could not read key from /dev/tty");
    }
}

/* Fill addr with a unix domain socket name for the agent. */
static int
agent_addr(struct sockaddr_un *addr, const uint8_t *iv)
{
    char *dir = getenv("XDG_RUNTIME_DIR");
    if (!dir) {
        dir = getenv("TMPDIR");
        if (!dir)
            dir = "/tmp";
    }
    addr->sun_family = AF_UNIX;
    if (strlen(dir) + 24 > sizeof(addr->sun_path)) {
        warning("agent socket path too long -- %s", dir);
        return 0;
    }
    else {
        sprintf(addr->sun_path,
                "%s/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", dir,
                iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7],
                iv[8], iv[9], iv[10], iv[11]);
        return 1;
    }
}

/* Read key from agent. Return 0 if it fails. */
static int
agent_read(uint8_t *key, const uint8_t *iv)
{
    int success = 0;
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (agent_addr(&addr, iv) &&
        !connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
        success = read(fd, key, 32) == 32;
    close(fd);
    return success;
}

/* Run agent. */
static int
agent_run(const uint8_t *key, const uint8_t *iv)
{
    struct pollfd pfd = {-1, POLLIN, 0};
    struct sockaddr_un addr;
    pid_t pid;

    pfd.fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (pfd.fd == -1) {
        warning("could not create agent socket");
        return 0;
    }
    if (!agent_addr(&addr, iv))
        return 0;

    pid = fork();
    if (pid == -1) {
        warning("could not fork() agent -- %s", strerror(errno));
        return 0;
    }
    else if (pid != 0) {
        return 1;
    }
    close(0);
    close(1);
    umask(~(S_IRUSR | S_IWUSR));

    if (unlink(addr.sun_path) && errno != ENOENT)
        fatal("failed to remove existing socket -- %s", strerror(errno));

    if (bind(pfd.fd, (struct sockaddr *)&addr, sizeof(addr))) {
        if (errno != EADDRINUSE)
            warning("could not bind agent socket %s -- %s",
                    addr.sun_path, strerror(errno));
            exit(EXIT_FAILURE);
    }

    if (listen(pfd.fd, SOMAXCONN)) {
        if (errno != EADDRINUSE)
            warning("could not listen on agent socket -- %s",
                    strerror(errno));
           exit(EXIT_FAILURE);
    }

    close(2); /* limit error messages from agent */
    for (;;) {
       int cfd;
       int r = poll(&pfd, 1, agent_timeout * 1000);
       if (r < 0) {
           unlink(addr.sun_path);
           fatal("agent poll failed -- %s", strerror(errno));
       }
       if (r == 0) {
           unlink(addr.sun_path);
           fputs("info: agent timeout\n", stderr);
           close(pfd.fd);
           break;
       }
       cfd = accept(pfd.fd, 0, 0);
       if (cfd != -1) {
           if (write(cfd, key, 32) != 32)
               warning("agent write failed");
           close(cfd);
       }
    }
    exit(EXIT_SUCCESS);
}

/* Initialize a SHA-256 context for HMAC-SHA256.
 * All message data will go into the resulting context. */
static void
hmac_init(SHA256_CTX *ctx, const uint8_t *key)
{
    int i;
    uint8_t pad[SHA256_BLOCK_SIZE];

    sha256_init(ctx);
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        pad[i] = key[i] ^ 0x36U;
    sha256_update(ctx, pad, sizeof(pad));
}

/* Compute the final HMAC-SHA256 MAC.
 * The key must be the same as used for initialization. */
static void
hmac_final(SHA256_CTX *ctx, const uint8_t *key, uint8_t *hash)
{
    int i;
    uint8_t pad[SHA256_BLOCK_SIZE];

    sha256_final(ctx, hash);
    sha256_init(ctx);
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
        pad[i] = key[i] ^ 0x5cU;
    sha256_update(ctx, pad, sizeof(pad));
    sha256_update(ctx, hash, SHA256_BLOCK_SIZE);
    sha256_final(ctx, hash);
}

/* Derive a 32-byte key from null-terminated passphrase into buf.
 * Optionally provide an 12-byte salt. */
static void
derive_key(const char *pass, uint8_t *key, int iexp, const uint8_t *salt)
{
    uint8_t salt32[SHA256_BLOCK_SIZE] = {0};
    SHA256_CTX ctx[1];
    unsigned long i;
    unsigned long memlen = 1UL << iexp;
    unsigned long mask = memlen - 1;
    unsigned long iterations = 1UL << (iexp - 5);
    uint8_t *memory, *memptr, *p;

    memory = malloc(memlen + SHA256_BLOCK_SIZE);
    if (!memory)
        fatal("not enough memory for key derivation");

    if (salt)
        memcpy(salt32, salt, 12);
    hmac_init(ctx, salt32);
    sha256_update(ctx, (uint8_t *)pass, strlen(pass));
    hmac_final(ctx, salt32, memory);

    for (p = memory + SHA256_BLOCK_SIZE;
         p < memory + memlen + SHA256_BLOCK_SIZE;
         p += SHA256_BLOCK_SIZE) {
        sha256_init(ctx);
        sha256_update(ctx, p - SHA256_BLOCK_SIZE, SHA256_BLOCK_SIZE);
        sha256_final(ctx, p);
    }

    memptr = memory + memlen - SHA256_BLOCK_SIZE;
    for (i = 0; i < iterations; i++) {
        unsigned long offset;
        sha256_init(ctx);
        sha256_update(ctx, memptr, SHA256_BLOCK_SIZE);
        sha256_final(ctx, memptr);
        offset = ((unsigned long)memptr[3] << 24 |
                  (unsigned long)memptr[2] << 16 |
                  (unsigned long)memptr[1] <<  8 |
                  (unsigned long)memptr[0] <<  0);
        memptr = memory + (offset & mask);
    }

    memcpy(key, memptr, SHA256_BLOCK_SIZE);
    free(memory);
}

/* Layout of secret key file */
#define SECFILE_IV            0
#define SECFILE_ITERATIONS    12
#define SECFILE_PROTECT_HASH  13
#define SECFILE_SECKEY        45
#define SECFILE_SIZE          (12 + 1 + 32 + 32)

/* Load KEY from KEYFILE, decrypting it if needed. */
static void
load_key(const char *keyfile, uint8_t *key)
{
    FILE *fd;
    CHACHA20_CTX cha[1];
    SHA256_CTX sha[1];
    uint8_t buf[SECFILE_SIZE];
    uint8_t protect[32];
    uint8_t protect_hash[SHA256_BLOCK_SIZE];
    int iexp;

    uint8_t *buf_iv           = buf + SECFILE_IV;
    uint8_t *buf_iterations   = buf + SECFILE_ITERATIONS;
    uint8_t *buf_protect_hash = buf + SECFILE_PROTECT_HASH;
    uint8_t *buf_seckey       = buf + SECFILE_SECKEY;

    fd = fopen(keyfile, "r");
    if (!fd)
        fatal("failed to open key file '%s' -- %s",
              keyfile, strerror(errno));
    if (!fread(buf, sizeof(buf), 1, fd))
        fatal("failed to read key file '%s'", keyfile);
    fclose(fd);

    iexp = buf_iterations[0];
    if (iexp) { /* key is encrypted */
        int agent_success = agent_read(protect, buf_iv);

        if (agent_success) {
            sha256_init(sha);
            sha256_update(sha, protect, 32);
            sha256_final(sha, protect_hash);
            agent_success = !memcmp(protect_hash, buf_protect_hash, 20);
        }

        if (!agent_success) {
            char pass[GEP_PASSWORD_MAX];

            get_pass(pass, "passphrase: ");
            derive_key(pass, protect, iexp, buf_iv);

            sha256_init(sha);
            sha256_update(sha, protect, sizeof(protect));
            sha256_final(sha, protect_hash);
            if (memcmp(protect_hash, buf_protect_hash, 32) != 0)
                fatal("wrong passphrase");
        }

        if (!agent_success && agent_timeout)
            agent_run(protect, buf_iv);

        chacha20_init(cha, protect, buf_iv);
        chacha20_encrypt(cha, buf_seckey, key, 32);
    }
    else
        memcpy(key, buf_seckey, 32);
}

/* Write KEY to KEYFILE. May encrypt KEY before writing. */
static void
write_key(char *keyfile, uint8_t *key, int iexp)
{
    int file;
    FILE *fd = NULL;
    CHACHA20_CTX cha[1];
    SHA256_CTX sha[1];
    uint8_t buf[SECFILE_SIZE] = {0};
    uint8_t protect[32];

    uint8_t *buf_iv           = buf + SECFILE_IV;
    uint8_t *buf_iterations   = buf + SECFILE_ITERATIONS;
    uint8_t *buf_protect_hash = buf + SECFILE_PROTECT_HASH;
    uint8_t *buf_seckey       = buf + SECFILE_SECKEY;

    if (iexp) {
        char pass[2][GEP_PASSWORD_MAX];

        get_pass(pass[0], "protection passphrase (empty for none): ");
        if (!pass[0][0])
            iexp = 0;
        else {
            get_pass(pass[1], "protection passphrase (repeat): ");
            if (strcmp(pass[0], pass[1]))
                fatal("passphrases don't match");

            secure_entropy(buf_iv, 12);
            derive_key(pass[0], protect, iexp, buf_iv);
            buf_iterations[0] = iexp;
            sha256_init(sha);
            sha256_update(sha, protect, sizeof(protect));
            sha256_final(sha, buf_protect_hash);
        }
    }

    if (iexp) {
        /* Encrypt using key derived from passphrase. */
        chacha20_init(cha, protect, buf_iv);
        chacha20_encrypt(cha, key, buf_seckey, 32);
    }
    else
        memcpy(buf_seckey, key, 32);

    file = open(keyfile, O_CREAT | O_WRONLY, 00600);
    if (file != -1)
        fd = fdopen(file, "w");
    if (!fd)
        fatal("could not open key file '%s' for writing", keyfile);
    if (!fwrite(buf, sizeof(buf), 1, fd)) {
        fclose(fd);
        remove(keyfile);
        fatal("could not write key file '%s'", keyfile);
    }
    if (fclose(fd)) {
        remove(keyfile);
        fatal("could not flush key file '%s'", keyfile, strerror(errno));
    }
}

/* Encrypt stream IN to stream OUT with AEAD_XChaCha20_Poly1305. */
static void
encrypt_stream(FILE *in, FILE *out,
               const uint8_t key[32], const uint8_t *aad, size_t aad_len)
{
    RFC8439_CTX ctx[1];
    uint8_t buffer[2][RFC8439_BLOCK_SIZE * 1024];
    uint8_t mac[RFC8439_MAC_SIZE];
    uint8_t subkey[32], nonce[24], subnonce[12];

    secure_entropy(nonce, 24);
    if (!fwrite(nonce, sizeof(nonce), 1, out))
        fatal("error writing nonce to ciphertext file");

    xchacha20_key(key, nonce, subkey, subnonce);
    rfc8439_init(ctx, subkey, subnonce, aad, aad_len);

    for (;;) {
        size_t z = fread(buffer[0], 1, sizeof(buffer[0]), in);

        if (!z) {
            if (ferror(in))
                fatal("error reading plaintext file");
            break;
        }
        rfc8439_encrypt(ctx, buffer[0], buffer[1], z);
        if (!fwrite(buffer[1], z, 1, out))
            fatal("error writing ciphertext file");
        if (z < sizeof(buffer[0]))
            break;
    }

    rfc8439_mac(ctx, mac);
    if (!fwrite(mac, sizeof(mac), 1, out))
        fatal("error writing checksum to ciphertext file");
    if (fflush(out))
        fatal("error flushing to ciphertext file -- %s", strerror(errno));
}

/* Decrypt stream IN to stream OUT with AEAD_XChaCha20_Poly1305. */
static void
decrypt_stream(FILE *in, FILE *out,
               const uint8_t key[32], const uint8_t *aad, size_t aad_len)
{
    RFC8439_CTX ctx[1];
    uint8_t buffer[2][RFC8439_BLOCK_SIZE * 1024 + RFC8439_MAC_SIZE];
    uint8_t subkey[32], nonce[24], subnonce[12];

    if (!(fread(nonce, sizeof(nonce), 1, in))) {
        if (ferror(in))
            fatal("cannot read ciphertext nonce");
        else
            fatal("ciphertext file too short for a nonce");
    }
    xchacha20_key(key, nonce, subkey, subnonce);
    rfc8439_init(ctx, subkey, subnonce, aad, aad_len);

    if (!(fread(buffer[0], RFC8439_MAC_SIZE, 1, in))) {
        if (ferror(in))
            fatal("cannot read ciphertext file");
        else
            fatal("ciphertext file too short");
    }
    for (;;) {
        uint8_t *p = buffer[0] + RFC8439_MAC_SIZE;
        size_t z = fread(p, 1, sizeof(buffer[0]) - RFC8439_MAC_SIZE, in);

        if (!z) {
            if (ferror(in))
                fatal("error reading ciphertext file");
            break;
        }
        rfc8439_decrypt(ctx, buffer[0], buffer[1], z);
        if (!fwrite(buffer[1], z, 1, out))
            fatal("error writing plaintext file");

        memmove(buffer[0], buffer[0] + z, RFC8439_MAC_SIZE);
        if (z < sizeof(buffer[0]) - RFC8439_MAC_SIZE)
            break;
    }

    if (!rfc8439_verify(ctx, buffer[0]))
        fatal("checksum mismatch");
    if (fflush(out))
        fatal("error flushing to plaintext file -- %s", strerror(errno));
}

/* Print a nice fingerprint of a key. */
static void
print_fingerprint(const uint8_t *key)
{
    int i;
    uint8_t hash[32];
    SHA256_CTX sha[1];

    sha256_init(sha);
    sha256_update(sha, key, 32);
    sha256_final(sha, hash);
    for (i = 0; i < 16; i += 4) {
        unsigned long chunk =
            ((unsigned long)hash[i + 0] << 24) |
            ((unsigned long)hash[i + 1] << 16) |
            ((unsigned long)hash[i + 2] <<  8) |
            ((unsigned long)hash[i + 3] <<  0);
        printf("%s%08lx", i ? "-" : "", chunk);
    }
    putchar('\n');
}

enum command {
    COMMAND_UNKNOWN = -2,
    COMMAND_AMBIGUOUS = -1,
    COMMAND_KEYGEN,
    COMMAND_ENCRYPT,
    COMMAND_DECRYPT,
    COMMAND_FINGERPRINT
};

static const char command_names[][12] = {
    "keygen", "encrypt", "decrypt", "fingerprint"
};

/* Parse the user's command into an enum. */
static enum command
parse_command(char *command)
{
    int found = COMMAND_UNKNOWN;
    size_t len = strlen(command);
    int ncommands = sizeof(command_names) / sizeof(*command_names);
    int i;

    if (command)
        for (i = 0; i < ncommands; i++) {
            if (strncmp(command, command_names[i], len) == 0) {
                if (found >= 0)
                    return COMMAND_AMBIGUOUS;
                found = i;
            }
        }
    return found;
}

static void
command_keygen(struct optparse *options)
{
    static const struct optparse_name keygen[] = {
        {"derive",      'd', OPTPARSE_NONE},
        {"edit",        'e', OPTPARSE_NONE},
        {"force",       'f', OPTPARSE_NONE},
        {"plain",       'u', OPTPARSE_NONE},
        {0, 0, 0}
    };
    int option, derive = 0, edit = 0, force = 0;

    int sec_iexp = GEP_SECKEY_ITERATIONS;
    int key_iexp = GEP_KEY_ITERATIONS;
    int exist;
    uint8_t key[32];

    while ((option = optparse(options, keygen)) != OPTPARSE_NONE) {
        switch (option) {
        case 'd':
            derive = 1;
            break;
        case 'e':
            edit = 1;
            break;
        case 'f':
            force = 1;
            break;
        case 'u':
            key_iexp = 0;
            break;
        case OPTPARSE_ERROR:
        default:
            fatal("%s", options->errmsg);
        }
    }
    if (edit && derive)
        fatal("--edit and --derive are mutually exclusive");

    exist = file_exists(keyfile);
    if (!edit && !force && exist)
        fatal("operation would clobber keyfile '%s'", keyfile);

    if (edit) {
        if (!exist)
            fatal("key file '%s' does not exist", keyfile);
        load_key(keyfile, key);
    }
    else if (derive) {
        char pass[2][GEP_PASSWORD_MAX];

        get_pass(pass[0], "key passphrase: ");
        get_pass(pass[1], "key passphrase (repeat): ");
        if (strcmp(pass[0], pass[1]))
            fatal("passphrases don't match");
        warning("deriving key from passphrase -- be patient...");
        derive_key(pass[0], key, sec_iexp, 0);
    }
    else
        secure_entropy(key, 32);

    write_key(keyfile, key, key_iexp);
}

static void
command_encrypt(struct optparse *options)
{
    static const struct optparse_name encrypt[] = {
        {"stdout", 'c', OPTPARSE_NONE},
        {"keep",   'k', OPTPARSE_NONE},
        {"aad",    256, OPTPARSE_REQUIRED},
        {0, 0, 0}
    };
    int option, tostdout = 0, keep = 0;
    const char *aad = gep_aad;
    char *infile, *outfile;
    FILE *in = stdin, *out = stdout;

    uint8_t key[32];

    while ((option = optparse(options, encrypt)) != OPTPARSE_NONE) {
        switch (option) {
        case 'c':
            tostdout = 1;
            keep = 1;
            break;
        case 'k':
            keep = 1;
            break;
        case 256:
            aad = options->optarg;
            break;
        case OPTPARSE_ERROR:
        default:
            fatal("%s", options->errmsg);
        }
    }

    load_key(keyfile, key);

    infile = optparse_arg(options);
    if (infile) {
        in = fopen(infile, "r");
        if (!in)
            fatal("could not open input file '%s' -- %s",
                  infile, strerror(errno));
    }

    outfile = dupstr(optparse_arg(options));
    if (outfile && tostdout)
        fatal("option --stdout and output file are mutually exclusive");
    if (!outfile && infile && !tostdout)
        outfile = joinstr(2, infile, gep_suffix);
    if (outfile) {
        out = fopen(outfile, "w");
        if (!out)
            fatal("could not open output file '%s' -- %s",
                  outfile, strerror(errno));
        fatal_ofd = out;
        fatal_oname = outfile;
    }

    encrypt_stream(in, out, key, (uint8_t *)aad, strlen(aad));

    if (in != stdin)
        fclose(in);
    if (out != stdout)
        fclose(out);
    if (!keep && infile)
        remove(infile);
}

static void
command_decrypt(struct optparse *options)
{
    static const struct optparse_name decrypt[] = {
        {"stdout", 'c', OPTPARSE_NONE},
        {"keep",   'k', OPTPARSE_NONE},
        {"aad",    256, OPTPARSE_REQUIRED},
        {0, 0, 0}
    };
    int option, tostdout = 0, keep = 0;
    const char *aad = gep_aad;
    char *infile, *outfile;
    FILE *in = stdin, *out = stdout;

    uint8_t key[32];

    while ((option = optparse(options, decrypt)) != OPTPARSE_NONE) {
        switch (option) {
        case 'c':
            tostdout = 1;
            keep = 1;
            break;
        case 'k':
            keep = 1;
            break;
        case 256:
            aad = options->optarg;
            break;
        case OPTPARSE_ERROR:
        default:
            fatal("%s", options->errmsg);
        }
    }

    load_key(keyfile, key);

    infile = optparse_arg(options);
    if (infile) {
        in = fopen(infile, "rb");
        if (!in)
            fatal("could not open input file '%s' -- %s",
                  infile, strerror(errno));
    }

    outfile = dupstr(optparse_arg(options));
    if (outfile && tostdout)
        fatal("option --stdout and output file are mutually exclusive");
    if (!outfile && infile && !tostdout) {
        size_t slen = sizeof(gep_suffix) - 1;
        size_t len = strlen(infile);
        if (len <= slen || strcmp(gep_suffix, infile + len - slen) != 0)
            fatal("could not determine output filename from %s", infile);
        outfile = dupstr(infile);
        outfile[len - slen] = 0;
    }
    if (outfile) {
        out = fopen(outfile, "w");
        if (!out)
            fatal("could not open output file '%s' -- %s",
                  outfile, strerror(errno));
        fatal_ofd = out;
        fatal_oname = outfile;
    }

    decrypt_stream(in, out, key, (uint8_t *)aad, strlen(aad));

    if (in != stdin)
        fclose(in);
    if (out != stdout)
        fclose(out);
    if (!keep && infile)
        remove(infile);
}

static void
command_fingerprint(struct optparse *options)
{
    static const struct optparse_name keygen[] = {
        {0, 0, 0}
    };
    int option;

    uint8_t key[32];

    while ((option = optparse(options, keygen)) != OPTPARSE_NONE) {
        switch (option) {
        case OPTPARSE_ERROR:
        default:
            fatal("%s", options->errmsg);
        }
    }
    load_key(keyfile, key);
    print_fingerprint(key);
}

int
main(int argc, char **argv)
{
    static const struct optparse_name global[] = {
        {"agent",       'a', OPTPARSE_OPTIONAL},
        {"no-agent",    'A', OPTPARSE_NONE},
        {"key",         'k', OPTPARSE_REQUIRED},
        {"version",     'V', OPTPARSE_NONE},
        {"help",        256, OPTPARSE_NONE},
        {0, 0, 0}
    };
    int option;
    char *command;
    struct optparse options[1];

    optparse_init(options, argv);
    while ((option = optparse(options, global)) != OPTPARSE_DONE) {
        switch (option) {
        case 'a':
            if (options->optarg) {
                char *endptr;

                errno = 0;
                agent_timeout = strtol(options->optarg, &endptr, 10);
                if (*endptr || errno)
                    fatal("invalid --agent argument -- %s", options->optarg);
            }
            else
                agent_timeout = GEP_AGENT_TIMEOUT;
            break;
        case 'A':
            agent_timeout = 0;
            break;
        case 'k':
            keyfile = options->optarg;
            break;
        case 'V':
            puts("gep " STR(GEP_VERSION));
            exit(EXIT_SUCCESS);
        case 256:
            printf("%s\n\n%s\n", docs_usage, docs_summary);
            exit(EXIT_SUCCESS);
        case OPTPARSE_ERROR:
        default:
            fprintf(stderr, "%s\n%s\n", options->errmsg, docs_usage);
            exit(EXIT_FAILURE);
        }
    }
    if (!keyfile)
        keyfile = default_keyfile();

    command = optparse_arg(options);

    switch (parse_command(command)) {
        case COMMAND_UNKNOWN:
        case COMMAND_AMBIGUOUS:
            fprintf(stderr, "gep: unknown command -- %s\n%s\n",
                command, docs_usage);
            exit(EXIT_FAILURE);
            break;
        case COMMAND_KEYGEN:
            command_keygen(options);
            break;
        case COMMAND_ENCRYPT:
            command_encrypt(options);
            break;
        case COMMAND_DECRYPT:
            command_decrypt(options);
            break;
        case COMMAND_FINGERPRINT:
            command_fingerprint(options);
            break;
    }

    return 0;
}
