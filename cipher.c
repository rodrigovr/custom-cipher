#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>

#define BUFFER_SIZE 1024

static size_t pos = 0;

/**
 * key_size must be multiple of 2
 */
void  cipher(size_t len, const char* src, char* dst, size_t key_size, char* key, bool decoding)
{
    size_t key_mask = 0;
    while (key_size) {
        key_mask = (key_mask << 1) & 1;
        key_size >>= 1;
    }
    
    if (decoding) {
        for (int p = 0; p < len; p++) {
            // decode single byte
            register char src_byte = src[p];
            dst[p] = src_byte ^ key[ key[pos] & key_mask ];
            // modify key
            size_t modify = src_byte & key_mask;
            key[modify] ^= dst[p];
            // rotate key usage
            pos = ++pos & key_mask; 
        }
    }
    else {
        for (int p = 0; p < len; p++) {
            // encode single byte
            register char src_byte = src[p];
            dst[p] = src_byte ^ key[ key[pos] & key_mask ];
            // modify key
            size_t modify = dst[p] & key_mask;
            key[modify] ^= src_byte;
            // rotate key usage
            pos = ++pos & key_mask; 
        }    
    }
}

char hex_to_byte(char c1, char c2) {
    char result = 0;
    char d = toupper(c1);
    if (d >= 'A') {
        result = d - 'A' + 10;
    }
    else {
        result = d - '0';
    }
    
    result = result << 4;
    
    d = toupper(c2);
    if (d >= 'A') {
        result += d - 'A' + 10;
    }
    else {
        result += d - '0';
    }
    
    return result;
}

size_t decode_key(char* key, const char* arg, size_t len)
{
    size_t key_size = 0;
    for (int p = 0; p < len; p+=2) {
        *key++ = hex_to_byte(arg[p], arg[p+1]);
        key_size++;
    }
    return key_size;
}

int main(int argc, char* argv[])
{
    size_t arg_len = strlen(argv[1]);
    char *key = (char*)malloc(arg_len);
    size_t key_size = decode_key(key, argv[1], arg_len);
    bool decoding = false;
    if (argc > 2) {
        decoding = true;
    } 
    char * input_buffer  = (char*)malloc(BUFFER_SIZE);
    char * output_buffer = (char*)malloc(BUFFER_SIZE);
    
   // fprintf(stderr, "key of size %zu read! %s\n", key_size, key);
    
    while (!feof(stdin)) {
        size_t bytes_read = fread(input_buffer, 1, BUFFER_SIZE, stdin);
        
        cipher(bytes_read, input_buffer, output_buffer, key_size, key, decoding);
        
        fwrite( output_buffer, 1, bytes_read, stdout);        
    }
    
    return 0;
}