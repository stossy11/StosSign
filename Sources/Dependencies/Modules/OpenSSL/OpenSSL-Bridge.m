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
    BIGNUM *bignum = NULL;
    RSA *rsa = NULL;
    X509_REQ *request = NULL;
    EVP_PKEY *publicKey = NULL;
    BIO *csr = NULL;
    BIO *privateKey = NULL;

    int success = 0;

    bignum = BN_new();
    if (bignum == NULL || BN_set_word(bignum, RSA_F4) != 1) {
        goto cleanup;
    }

    rsa = RSA_new();
    if (rsa == NULL || RSA_generate_key_ex(rsa, 2048, bignum, NULL) != 1) {
        goto cleanup;
    }

    /* Generate request */
    request = X509_REQ_new();
    if (request == NULL || X509_REQ_set_version(request, 1) != 1) {
        goto cleanup;
    }

    const char *country = "US";
    const char *state = "CA";
    const char *city = "Los Angeles";
    const char *organization = "StosSign";
    const char *commonName = "StosSign";

    X509_NAME *subject = X509_REQ_get_subject_name(request);
    if (subject == NULL) {
        goto cleanup;
    }

    X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, (const unsigned char *)country, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "ST", MBSTRING_ASC, (const unsigned char *)state, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "L", MBSTRING_ASC, (const unsigned char *)city, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, (const unsigned char *)organization, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char *)commonName, -1, -1, 0);

    publicKey = EVP_PKEY_new();
    if (publicKey == NULL || EVP_PKEY_assign_RSA(publicKey, rsa) != 1) {
        goto cleanup;
    }

    if (X509_REQ_set_pubkey(request, publicKey) != 1) {
        goto cleanup;
    }

    if (X509_REQ_sign(request, publicKey, EVP_sha256()) <= 0) {
        goto cleanup;
    }

    csr = BIO_new(BIO_s_mem());
    if (csr == NULL || PEM_write_bio_X509_REQ(csr, request) != 1) {
        goto cleanup;
    }

    privateKey = BIO_new(BIO_s_mem());
    if (privateKey == NULL || PEM_write_bio_RSAPrivateKey(privateKey, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
        goto cleanup;
    }

    /* Extract Data */
    char *csrData = NULL;
    *requestLength = BIO_get_mem_data(csr, &csrData);
    *outputRequest = (unsigned char *)malloc(*requestLength);
    memcpy(*outputRequest, csrData, *requestLength);

    char *privateKeyData = NULL;
    *privateKeyLength = BIO_get_mem_data(privateKey, &privateKeyData);
    *outputPrivateKey = (unsigned char *)malloc(*privateKeyLength);
    memcpy(*outputPrivateKey, privateKeyData, *privateKeyLength);

    success = 1;

cleanup:
    if (publicKey != NULL) {
        EVP_PKEY_free(publicKey);
    } else {
        RSA_free(rsa);
    }

    BN_free(bignum);
    X509_REQ_free(request);
    BIO_free_all(csr);
    BIO_free_all(privateKey);

    return success;
}
