static const char *docs_usage =
"usage: gep [-a|--agent[=<seconds>]] [-A|--no-agent] [-k|--key <file>]\n"
"           [-V|--version] [--help] <command> [<args>]\n"
"\n"
"       commands:\n"
"           keygen [-d|--derive] [-e|--edit] [-f|--force] [-u|--plain]\n"
"           encrypt [-c|--stdout] [-k|--keep] [--aad <string>]\n"
"                   [<infile> [<outfile>]]\n"
"           decrypt [-c|--stdout] [-k|--keep] [--aad <string>]\n"
"                   [<infile> [<outfile>]]\n"
"           edit [--no-backup] [-aad <string>] <infile>\n"
"           fingerprint";

static const char *docs_summary =
"gep encrypts files with AEAD_XChaCha20_Poly1305.";

