#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <argp.h>

#include "rutoken-ecp.h"
#include "dbg.h"

void main(int argc, char *argv[])
{

    FILE *input_file = NULL;
    FILE *signature_file = NULL;
    char *signature_name = NULL;
    uint8_t *buffer = NULL;
    uint8_t *signature = NULL;

    check(argc == 5, "Usage: rutoken-sign <file> <user_pin> <key_pair_id> <slot>");

    char *file_name = argv[1];
    char *user_pin = argv[2];
    char *key_pair_id = argv[3];
    int slot = atoi(argv[4]);

    input_file = fopen(file_name, "rb");
    check(input_file, "Could not open file %s", file_name);

    size_t signature_name_size = strlen(file_name) + 5;
    signature_name = calloc(signature_name_size, sizeof(char));
    check_mem(signature_name);
    check(snprintf(signature_name, signature_name_size, "%s.sign", file_name) == signature_name_size, "Could not compose the signature file name");

    check(fseek(input_file, 0, SEEK_END) != -1, "Could not seek inside the input file");
    long input_file_size = ftell(input_file);
    check(fseek(input_file, 0, SEEK_SET) != -1, "Could not seek inside the input file");

    buffer = calloc(input_file_size, sizeof(uint8_t));
    check_mem(buffer);

    check(fread(buffer, 1, input_file_size, input_file) == input_file_size, "Could not read the input file");

    size_t signature_size = 0;
    signature = sign(buffer, input_file_size, &signature_size, user_pin, strlen(user_pin), key_pair_id, strlen(key_pair_id), slot);
    check_mem(signature);
    check(signature_size > 0, "Could not sign the input file");

    signature_file = fopen(signature_name, "wb");
    check(signature_file, "Could not open the signature file %s", signature_name);
    check(fwrite(signature, 1, signature_size, signature_file) == signature_size, "Could not write the signature to the file");

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