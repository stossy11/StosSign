//
//  OpenSSL.h
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//

#ifndef OPENSSL_CERTIFICATE_UTILS_H
#define OPENSSL_CERTIFICATE_UTILS_H

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline long BIO_get_mem_ptr_bridge(BIO *bio, const unsigned char **pp) {
    return BIO_get_mem_ptr(bio, pp); //BIO_get_mem_data(bio, pp);
}


bool parse_certificate_data(const unsigned char *pemData, int pemDataLength,
                          char **outName, size_t *outNameLength,
                          char **outSerialNumber, size_t *outSerialNumberLength);


bool create_p12_data(const unsigned char *certData, int certDataLength,
                    const unsigned char *privateKeyData, int privateKeyDataLength,
                    const char *password,
                    unsigned char **outP12Data, size_t *outP12DataLength);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_CERTIFICATE_UTILS_H */
