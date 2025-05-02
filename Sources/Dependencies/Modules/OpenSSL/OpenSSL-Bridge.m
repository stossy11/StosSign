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


bool parse_certificate_data(const unsigned char *pemData, int pemDataLength,
                          char **outName, size_t *outNameLength,
                          char **outSerialNumber, size_t *outSerialNumberLength) {
    BIO *certificateBuffer = NULL;
    X509 *certificate = NULL;
    BIGNUM *number = NULL;
    char *cSerialNumber = NULL;
    bool result = false;

    certificateBuffer = BIO_new_mem_buf((const void *)pemData, pemDataLength);
    if (!certificateBuffer) {
        goto cleanup;
    }
    
    certificate = NULL;
    PEM_read_bio_X509(certificateBuffer, &certificate, 0, 0);
    if (certificate == NULL) {
        goto cleanup;
    }

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

    ASN1_INTEGER *serialNumberData = X509_get_serialNumber(certificate);
    number = ASN1_INTEGER_to_BN(serialNumberData, NULL);
    if (number == NULL) {
        goto cleanup;
    }

    cSerialNumber = BN_bn2hex(number);
    if (cSerialNumber == NULL) {
        goto cleanup;
    }

    *outNameLength = strlen((const char *)cName) + 1;
    *outName = (char *)malloc(*outNameLength);
    strcpy(*outName, (const char *)cName);

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
    BIO *certificateBuffer = BIO_new(BIO_s_mem());
    BIO *privateKeyBuffer = BIO_new(BIO_s_mem());
    bool result = false;
    
    if (!certificateBuffer || !privateKeyBuffer) {
        goto cleanup;
    }

    BIO_write(certificateBuffer, certData, certDataLength);
    BIO_write(privateKeyBuffer, privateKeyData, privateKeyDataLength);

    X509 *certificate = NULL;
    PEM_read_bio_X509(certificateBuffer, &certificate, 0, 0);
    if (!certificate) {
        goto cleanup;
    }

    EVP_PKEY *privateKey = NULL;
    PEM_read_bio_PrivateKey(privateKeyBuffer, &privateKey, 0, 0);
    if (!privateKey) {
        X509_free(certificate);
        goto cleanup;
    }

    char emptyString[] = "";
    PKCS12 *outputP12 = PKCS12_create(password ? (char *)password : "",
                                    emptyString, privateKey, certificate,
                                    NULL, 0, 0, 0, 0, 0);
    if (!outputP12) {
        EVP_PKEY_free(privateKey);
        X509_free(certificate);
        goto cleanup;
    }

    BIO *p12Buffer = BIO_new(BIO_s_mem());
    i2d_PKCS12_bio(p12Buffer, outputP12);

    char *buffer = NULL;
    *outP12DataLength = BIO_get_mem_data(p12Buffer, &buffer);
    *outP12Data = (unsigned char *)malloc(*outP12DataLength);
    memcpy(*outP12Data, buffer, *outP12DataLength);

    BIO_free(p12Buffer);
    PKCS12_free(outputP12);
    EVP_PKEY_free(privateKey);
    X509_free(certificate);
    
    result = true;

cleanup:
    if (certificateBuffer) {
        BIO_free(certificateBuffer);
    }
    if (privateKeyBuffer) {
        BIO_free(privateKeyBuffer);
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
    const char *organization = "AltSign";
    const char *commonName = "AltSign";

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


CertificateOutput CertificatesContent(
    const unsigned char* p12Data,
    size_t p12Length,
    const char* appleRootCertData,
    const char* appleWWDRCertData,
    const char* legacyAppleWWDRCertData) {
    CertificateOutput output = { NULL, 0 };

    BIO* inputP12Buffer = BIO_new(BIO_s_mem());
    BIO_write(inputP12Buffer, p12Data, (int)p12Length);

    PKCS12* inputP12 = d2i_PKCS12_bio(inputP12Buffer, NULL);
    if (!inputP12) goto cleanup;

    EVP_PKEY* key = NULL;
    X509* certificate = NULL;
    if (!PKCS12_parse(inputP12, "", &key, &certificate, NULL)) goto cleanup;

    STACK_OF(X509)* certificates = sk_X509_new_null();

    BIO* rootCertificateBuffer = BIO_new_mem_buf((void*)appleRootCertData, (int)strlen(appleRootCertData));
    BIO* wwdrCertificateBuffer = NULL;

    unsigned long issuerHash = X509_issuer_name_hash(certificate);
    if (issuerHash == 0x817d2f7a) {
        wwdrCertificateBuffer = BIO_new_mem_buf((void*)legacyAppleWWDRCertData, (int)strlen(legacyAppleWWDRCertData));
    } else {
        wwdrCertificateBuffer = BIO_new_mem_buf((void*)appleWWDRCertData, (int)strlen(appleWWDRCertData));
    }

    X509* rootCertificate = PEM_read_bio_X509(rootCertificateBuffer, NULL, NULL, NULL);
    if (rootCertificate) sk_X509_push(certificates, rootCertificate);

    X509* wwdrCertificate = PEM_read_bio_X509(wwdrCertificateBuffer, NULL, NULL, NULL);
    if (wwdrCertificate) sk_X509_push(certificates, wwdrCertificate);

    PKCS12* outputP12 = PKCS12_create("", "", key, certificate, certificates, 0, 0, 0, 0, 0);
    if (!outputP12) goto cleanup;

    BIO* outputP12Buffer = BIO_new(BIO_s_mem());
    i2d_PKCS12_bio(outputP12Buffer, outputP12);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(outputP12Buffer, &bptr);
    output.bytes = (unsigned char*)malloc(bptr->length);
    memcpy(output.bytes, bptr->data, bptr->length);
    output.length = bptr->length;

    BIO_free(outputP12Buffer);
    PKCS12_free(outputP12);

cleanup:
    if (inputP12) PKCS12_free(inputP12);
    if (key) EVP_PKEY_free(key);
    if (certificate) X509_free(certificate);
    if (certificates) sk_X509_pop_free(certificates, X509_free);
    if (rootCertificateBuffer) BIO_free(rootCertificateBuffer);
    if (wwdrCertificateBuffer) BIO_free(wwdrCertificateBuffer);
    if (inputP12Buffer) BIO_free(inputP12Buffer);

    return output;
}
