//
//  OpenSSL-Bridging.c
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//

#include "OpenSSL-Bridge.h"


bool create_p12_data(const unsigned char *certData, int certDataLength,
                    const unsigned char *privateKeyData, int privateKeyDataLength,
                    const char *password,
                    unsigned char **outP12Data, size_t *outP12DataLength) {
    X509 *certificate = NULL;
    EVP_PKEY *privateKey = NULL;
    PKCS12 *outputP12 = NULL;
    BIO *p12Buffer = NULL;
    bool result = false;
    
    // Try to parse certificate - first as PEM, then as DER
    BIO *certBio = BIO_new_mem_buf((const void *)certData, certDataLength);
    if (!certBio) {
        goto cleanup;
    }
    
    certificate = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
    if (!certificate) {
        // Reset BIO and try DER format
        BIO_free(certBio);
        certBio = BIO_new_mem_buf((const void *)certData, certDataLength);
        certificate = d2i_X509_bio(certBio, NULL);
        if (!certificate) {
            fprintf(stderr, "Failed to parse certificate as PEM or DER\n");
            goto cleanup;
        }
    }
    BIO_free(certBio);
    certBio = NULL;
    
    // Try to parse private key - first as PEM, then as DER
    BIO *keyBio = BIO_new_mem_buf((const void *)privateKeyData, privateKeyDataLength);
    if (!keyBio) {
        goto cleanup;
    }
    
    privateKey = PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
    if (!privateKey) {
        // Reset BIO and try DER format
        BIO_free(keyBio);
        keyBio = BIO_new_mem_buf((const void *)privateKeyData, privateKeyDataLength);
        privateKey = d2i_AutoPrivateKey(NULL, (const unsigned char **)&privateKeyData, privateKeyDataLength);
        if (!privateKey) {
            fprintf(stderr, "Failed to parse private key as PEM or DER\n");
            goto cleanup;
        }
    }
    BIO_free(keyBio);
    keyBio = NULL;

    // Create PKCS12 structure
    char emptyString[] = "";
    const char *p12Password = (password && strlen(password) > 0) ? password : "";
    
    outputP12 = PKCS12_create((char *)p12Password,
                              emptyString,
                              privateKey,
                              certificate,
                              NULL,  // No additional certificates
                              0,     // Default encryption for private key
                              0,     // Default encryption for certificate
                              0,     // Default iteration count
                              0,     // Default MAC iteration count
                              0);    // Default key type
    if (!outputP12) {
        fprintf(stderr, "PKCS12_create failed\n");
        goto cleanup;
    }

    // Convert PKCS12 to DER format
    p12Buffer = BIO_new(BIO_s_mem());
    if (!p12Buffer) {
        goto cleanup;
    }
    
    if (i2d_PKCS12_bio(p12Buffer, outputP12) != 1) {
        fprintf(stderr, "i2d_PKCS12_bio failed\n");
        goto cleanup;
    }

    // Extract the data
    char *buffer = NULL;
    *outP12DataLength = BIO_get_mem_data(p12Buffer, &buffer);
    if (*outP12DataLength == 0) {
        fprintf(stderr, "No P12 data generated\n");
        goto cleanup;
    }
    
    *outP12Data = (unsigned char *)malloc(*outP12DataLength);
    if (!*outP12Data) {
        goto cleanup;
    }
    memcpy(*outP12Data, buffer, *outP12DataLength);
    
    result = true;

cleanup:
    if (certBio) {
        BIO_free(certBio);
    }
    if (keyBio) {
        BIO_free(keyBio);
    }
    if (certificate) {
        X509_free(certificate);
    }
    if (privateKey) {
        EVP_PKEY_free(privateKey);
    }
    if (outputP12) {
        PKCS12_free(outputP12);
    }
    if (p12Buffer) {
        BIO_free(p12Buffer);
    }
    
    return result;
}
