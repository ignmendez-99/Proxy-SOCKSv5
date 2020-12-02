#ifndef PC_2020B_6_BASE64_H
#define PC_2020B_6_BASE64_H

/**
 * Credito del codigo: https://nachtimwald.com/2017/11/18/base64-encode-and-decode-in-c/
 * */

size_t b64_decoded_size(const char *in);

int b64_decode(const char *in, unsigned char *out, size_t outlen);


#endif //PC_2020B_6_BASE64_H
