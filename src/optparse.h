#ifndef OPTPARSE_H
#define OPTPARSE_H

/* Parse short and long options.
 * Short options may be grouped.
 * Options may have one optional or required argument.
 *
 * Examples: [-f|--foo] [(-b|--bar) [<file>]] [(-q|--qux) <file>]
 *   program -f -b            # b has no argument
 *   program -fb              # same
 *   program -f -b file       # file is a non-option argument
 *   program -f -bfile        # file is the argument of b
 *   program -fbfile          # same
 *   program -f -q file       # file is the argument of q
 *   program -fq file         # same
 *   program -fqfile          # same
 *   program --foo --bar file # file is a non-option argument
 *   program --foo --bar=file # file is the argument of bar
 *   program --foo --qux file # file is the argument of qux
 *   program --foo --qux=file # same
 *   program --foo -- --bar   # --bar is an non-option argument
 *
 * To get the implementation, define OPTPARSE_IMPLEMENTATION.
 * Optionally define OPTPARSE_API to control the API's visibility
 * and/or linkage (static, __attribute__, __declspec).
 */

#ifndef OPTPARSE_API
#define OPTPARSE_API
#endif

#define OPTPARSE_DONE  0
#define OPTPARSE_ERROR -1

struct optparse {
    char **argv;
    int optind;
    char *optarg;
    char errmsg[64];
    int subopt;
};

enum optparse_argtype {
    OPTPARSE_NONE,
    OPTPARSE_REQUIRED,
    OPTPARSE_OPTIONAL
};

struct optparse_name {
    const char *longname;          /* NULL if longname does not exist */
    int shortname;                 /* >255 if shortname does not exist */
    enum optparse_argtype argtype;
};

/* Initialize the parser state. */
OPTPARSE_API
void optparse_init(struct optparse *options, char **argv);

/* Read the next option in the argv array.
 * Return the next option short name, DONE or ERROR.
 * The end of the names array is marked with an all zeros entry. */
OPTPARSE_API
int optparse(struct optparse *options, const struct optparse_name *names);

/* Step over non-option arguments.
 * Return the next non-option argument, or NULL for no more arguments.
 * Argument parsing can continue with optparse() after using this function:
 * you may want to parse subcommands options. */
OPTPARSE_API
char *optparse_arg(struct optparse *options);

/* Implementation. */
#ifdef OPTPARSE_IMPLEMENTATION

#define MSG_INVALID "invalid option"
#define MSG_MISSING "option requires an argument"
#define MSG_TOOMANY "option takes no arguments"

static int
error(struct optparse *options, const char *msg, const char *data)
{
    const char *sep = " -- '";
    int i = 0;

    while (*msg)
        options->errmsg[i++] = *msg++;
    while (*sep)
        options->errmsg[i++] = *sep++;
    while (i < sizeof(options->errmsg) - 2 && *data)
        options->errmsg[i++] = *data++;
    options->errmsg[i++] = '\'';
    options->errmsg[i] = 0;
    return OPTPARSE_ERROR;
}

static int
name_match(const char *longname, const char *option)
{
    const char *a = option, *n = longname;

    if (longname == 0)
        return 0;
    for (; *a && *n && *a != '='; a++, n++)
        if (*a != *n)
            return 0;
    return *n == '\0' && (*a == '\0' || *a == '=');
}

static char *
name_arg(char *option)
{
    for (; *option && *option != '='; option++);
    if (*option == '=')
        return option + 1;
    else
        return 0;
}

OPTPARSE_API
void
optparse_init(struct optparse *options, char **argv)
{
    options->argv = argv;
    options->optind = 1;
    options->subopt = 0;
    options->optarg = 0;
    options->errmsg[0] = 0;
}

OPTPARSE_API
int
optparse(struct optparse *options, const struct optparse_name *names)
{
    int i;
    char *option;

    options->errmsg[0] = 0;
    options->optarg = 0;
    if (!(option = options->argv[options->optind]))
        return OPTPARSE_DONE;

    /* '--' end of options */
    if (option[0] == '-' && option[1] == '-' && option[2] == 0) {
        options->optind++;
        return OPTPARSE_DONE;
    }

    /* short options */
    if (option[0] == '-' && option[1] != '-' && option[1] != 0) {
        char str[2] = {0, 0};

        option += options->subopt + 1;
        for (i = 0; names[i].longname || names[i].shortname; i++) {
            int name = names[i].shortname;

            if (name == option[0]) {
                switch (names[i].argtype) {
                case OPTPARSE_NONE:
                    if(option[1])
                        options->subopt++;
                    else {
                        options->subopt = 0;
                        options->optind++;
                    }
                    break;
                case OPTPARSE_REQUIRED:
                    options->subopt = 0;
                    options->optind++;
                    if (option[1])
                        options->optarg = option + 1;
                    else if ((options->optarg = options->argv[options->optind]))
                        options->optind++;
                    else {
                        str[0] = option[0];
                        return error(options, MSG_MISSING, str);
                    }
                    break;
                default: /* OPTPARSE_OPTIONAL */
                    options->subopt = 0;
                    options->optind++;
                    if (option[1])
                        options->optarg = option + 1;
                    else
                        options->optarg = 0;
                    break;
                }
                return option[0];
            }
        }
        options->optind++;
        str[0] = option[0];
        return error(options, MSG_INVALID, str);
    }

    /* long option */
    if (option[0] == '-' && option[1] == '-' && option[2] != 0) {
        option += 2; /* skip "--" */
        options->optind++;

        for (i = 0; names[i].longname || names[i].shortname; i++) {
            const char *name = names[i].longname;

            if (name_match(name, option)) {
                char *arg = name_arg(option);

                switch (names[i].argtype) {
                case OPTPARSE_NONE:
                    if (arg)
                        return error(options, MSG_TOOMANY, name);
                    break;
                case OPTPARSE_REQUIRED:
                    if (arg)
                        options->optarg = arg;
                    else {
                        options->optarg = options->argv[options->optind++];
                        if (!options->optarg)
                            return error(options, MSG_MISSING, name);
                    }
                    break;
                default: /* OPTPARSE_OPTIONAL */
                    if (arg)
                        options->optarg = arg;
                    break;
                }
                return names[i].shortname;
            }
        }
        return error(options, MSG_INVALID, option);
    }

    return OPTPARSE_DONE;
}

OPTPARSE_API
char *
optparse_arg(struct optparse *options)
{
    char *option = options->argv[options->optind];

    options->subopt = 0;
    if (option != 0)
        options->optind++;
    return option;
}

#endif /* OPTPARSE_IMPLEMENTATION */
#endif /* OPTPARSE_H */
