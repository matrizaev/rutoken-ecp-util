#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <argp.h>

#include "rutoken-ecp.h"
#include "dbg.h"

const char *argp_program_version =
    "rutoken-ecp-util 0.1.0";
const char *argp_program_bug_address =
    "<matrizaev@gmail.com>";

/* Program documentation. */
static char doc[] =
    "rutoken-ecp-util -- list (Rutoken tokens, key pairs) or sign a provided file";

static char args_doc[] = "(list|sign <FILE>)";

/* The options we understand. */
static struct argp_option options[] = {
    {"slot", 's', "SLOT", 0, "The slot number. Default is 0"},
    {"pin", 'p', "USER_PIN", 0, "User pin. Default is 12345678"},
    {"key_pair", 'k', "KEY_PAIR_ID", 0, "Key pair ID. Default is <empty>"},
    {0}};

/* Used by main to communicate with parse_opt. */
struct arguments
{
    char *args[2]; /* command & input_file */
    size_t slot;
    char *user_pin;
    char *key_pair_id;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which is a
       pointer to our arguments structure. */
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 's':
        arguments->slot = atoi(arg);
        break;
    case 'p':
        arguments->user_pin = arg;
    case 'k':
        arguments->key_pair_id = arg;
        break;

    case ARGP_KEY_ARG:

        if (state->arg_num > 1)
            argp_usage(state);
        if ((state->arg_num == 1) && strcmp(arguments->args[0], "list") == 0)
            argp_usage(state);
        if ((state->arg_num == 0) && strcmp(arg, "sign") != 0 && strcmp(arg, "list") != 0)
            argp_usage(state);
        arguments->args[state->arg_num] = arg;
        break;

    case ARGP_KEY_END:
        if (state->arg_num < 1 || (state->arg_num < 2 && !strcmp(arguments->args[0], "sign")))
            /* Not enough arguments. */
            argp_usage(state);
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

void main(int argc, char *argv[])
{

    struct arguments arguments;
    arguments.slot = 0;
    arguments.user_pin = "12345678"; // default user pin
    arguments.key_pair_id = "";      // default key pair id
    arguments.args[0] = NULL;
    arguments.args[1] = NULL;

    FILE *input_file = NULL;
    FILE *signature_file = NULL;
    char *signature_name = NULL;
    uint8_t *buffer = NULL;
    uint8_t *signature = NULL;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    char *command = arguments.args[0];
    char *file_name = arguments.args[1];

    if (strcmp(command, "list") == 0)
    {
        list_token(arguments.user_pin, strlen(arguments.user_pin), arguments.slot);
    }
    else if (strcmp(command, "sign") == 0)
    {

        input_file = fopen(file_name, "rb");
        check(input_file, "Could not open file %s", file_name);

        size_t signature_name_size = strlen(file_name) + 6;
        signature_name = calloc(signature_name_size, sizeof(char));
        check_mem(signature_name);
        check(snprintf(signature_name, signature_name_size, "%s.sign", file_name) == signature_name_size - 1, "Could not compose the signature file name");

        check(fseek(input_file, 0, SEEK_END) != -1, "Could not seek inside the input file");
        long input_file_size = ftell(input_file);
        check(fseek(input_file, 0, SEEK_SET) != -1, "Could not seek inside the input file");

        buffer = calloc(input_file_size, sizeof(uint8_t));
        check_mem(buffer);

        check(fread(buffer, 1, input_file_size, input_file) == input_file_size, "Could not read the input file");

        size_t signature_size = 0;
        signature = sign(buffer, input_file_size, &signature_size, arguments.user_pin, strlen(arguments.user_pin), arguments.key_pair_id, strlen(arguments.key_pair_id), arguments.slot);
        check_mem(signature);
        check(signature_size > 0, "Could not sign the input file");

        signature_file = fopen(signature_name, "wb");
        check(signature_file, "Could not open the signature file %s", signature_name);
        check(fwrite(signature, 1, signature_size, signature_file) == signature_size, "Could not write the signature to the file");
    }
    else
    {
        puts("Unknown command");
    }
error:
    if (input_file)
        fclose(input_file);
    if (signature_name)
        free(signature_name);
    if (buffer)
        free(buffer);
    if (signature)
        free(signature);
    if (signature_file)
        fclose(signature_file);
    return;
}