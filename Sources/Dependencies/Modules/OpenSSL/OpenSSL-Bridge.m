//
//  OpenSSL-Bridging.m
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//

#include "OpenSSL-Bridge.h"

bool parse_p12_data(const unsigned char *p12Data, int p12DataLength,
                   const char *password,
                   unsigned char **outCertData, size_t *outCertDataLength,
                   unsigned char **outPrivateKeyData, size_t *outPrivateKeyLength) {
    BIO *inputP12Buffer = BIO_new_mem_buf((const void *)p12Data, p12DataLength);
    PKCS12 *inputP12 = d2i_PKCS12_bio(inputP12Buffer, NULL);
    BIO_free(inputP12Buffer);
    
    if (inputP12 == NULL) {
        return false;
    }

    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    PKCS12_parse(inputP12, password, &key, &certificate, NULL);
    PKCS12_free(inputP12);

    if (key == NULL || certificate == NULL) {
        if (key) EVP_PKEY_free(key);
        if (certificate) X509_free(certificate);
        return false;
    }

    BIO *pemBuffer = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(pemBuffer, certificate);

    BIO *privateKeyBuffer = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privateKeyBuffer, key, NULL, NULL, 0, NULL, NULL);

    char *pemBytes = NULL;
    *outCertDataLength = BIO_get_mem_data(pemBuffer, &pemBytes);
    *outCertData = (unsigned char *)malloc(*outCertDataLength);
    memcpy(*outCertData, pemBytes, *outCertDataLength);

    char *privateKeyBytes = NULL;
    *outPrivateKeyLength = BIO_get_mem_data(privateKeyBuffer, &privateKeyBytes);
    *outPrivateKeyData = (unsigned char *)malloc(*outPrivateKeyLength);
    memcpy(*outPrivateKeyData, privateKeyBytes, *outPrivateKeyLength);

    EVP_PKEY_free(key);
    X509_free(certificate);
    BIO_free(pemBuffer);
    BIO_free(privateKeyBuffer);

    return true;
}


bool parse_certificate_data(const unsigned char *derData, int derDataLength,
                            char **outName, size_t *outNameLength,
                            char **outSerialNumber, size_t *outSerialNumberLength) {
    BIO *certificateBuffer = NULL;
    X509 *certificate = NULL;
    BIGNUM *number = NULL;
    char *cSerialNumber = NULL;
    bool result = false;
    
    // Create BIO from DER data
    certificateBuffer = BIO_new_mem_buf((const void *)derData, derDataLength);
    if (!certificateBuffer) {
        goto cleanup;
    }
    
    // Parse DER format (not PEM!)
    certificate = d2i_X509_bio(certificateBuffer, NULL);
    if (certificate == NULL) {
        goto cleanup;
    }
    
    // Extract common name
    X509_NAME *subject = X509_get_subject_name(certificate);
    int index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (index == -1) {
        goto cleanup;
    }
    
    X509_NAME_ENTRY *nameEntry = X509_NAME_get_entry(subject, index);
    ASN1_STRING *nameData = X509_NAME_ENTRY_get_data(nameEntry);
    const unsigned char *cName = ASN1_STRING_get0_data(nameData);
    if (cName == NULL) {
        goto cleanup;
    }
    
    // Extract serial number
    ASN1_INTEGER *serialNumberData = X509_get_serialNumber(certificate);
    number = ASN1_INTEGER_to_BN(serialNumberData, NULL);
    if (number == NULL) {
        goto cleanup;
    }
    
    cSerialNumber = BN_bn2hex(number);
    if (cSerialNumber == NULL) {
        goto cleanup;
    }
    
    // Copy name
    *outNameLength = strlen((const char *)cName) + 1;
    *outName = (char *)malloc(*outNameLength);
    strcpy(*outName, (const char *)cName);
    
    // Copy serial number (skip leading zeros)
    int i = 0;
    while (cSerialNumber[i] == '0' && cSerialNumber[i+1] != '\0') {
        i++;
    }
    *outSerialNumberLength = strlen(&cSerialNumber[i]) + 1;
    *outSerialNumber = (char *)malloc(*outSerialNumberLength);
    strcpy(*outSerialNumber, &cSerialNumber[i]);
    
    result = true;

cleanup:
    if (certificateBuffer) {
        BIO_free(certificateBuffer);
    }
    if (certificate) {
        X509_free(certificate);
    }
    if (number) {
        BN_free(number);
    }
    if (cSerialNumber) {
        OPENSSL_free(cSerialNumber);
    }
    
    return result;
}


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

int generate_certificate_request(unsigned char **outputRequest, long *requestLength,
                                unsigned char **outputPrivateKey, long *privateKeyLength) {
    EVP_PKEY *pkey = NULL;
    X509_REQ *request = NULL;
    BIO *csrBio = NULL;
    BIO *keyBio = NULL;
    int success = 0;

    pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    if (pkey == NULL) goto cleanup;

    request = X509_REQ_new();
    if (request == NULL || X509_REQ_set_version(request, 0) != 1) goto cleanup;

    X509_NAME *subject = X509_REQ_get_subject_name(request);
    X509_NAME_add_entry_by_txt(subject, "C",  MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "ST", MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "L",  MBSTRING_ASC, (unsigned char *)"Los Angeles", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "O",  MBSTRING_ASC, (unsigned char *)"StosSign", -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (unsigned char *)"StosSign", -1, -1, 0);

    if (X509_REQ_set_pubkey(request, pkey) != 1) goto cleanup;

    if (X509_REQ_sign(request, pkey, EVP_sha256()) <= 0) goto cleanup;

    csrBio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509_REQ(csrBio, request) != 1) goto cleanup;

    keyBio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(keyBio, pkey, NULL, NULL, 0, NULL, NULL) != 1) goto cleanup;

    char *data = NULL;
    *requestLength = BIO_get_mem_data(csrBio, &data);
    *outputRequest = (unsigned char *)malloc(*requestLength);
    memcpy(*outputRequest, data, *requestLength);

    *privateKeyLength = BIO_get_mem_data(keyBio, &data);
    *outputPrivateKey = (unsigned char *)malloc(*privateKeyLength);
    memcpy(*outputPrivateKey, data, *privateKeyLength);

    success = 1;

cleanup:
    X509_REQ_free(request);
    EVP_PKEY_free(pkey);
    BIO_free_all(csrBio);
    BIO_free_all(keyBio);
    return success;
}
