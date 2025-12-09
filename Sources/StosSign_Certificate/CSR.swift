//
//  CSR.swift
//  StosSign
//
//  Created by Stossy11 on 09/12/2025.
//

// I had to do this in a new target because Certificate from swift-certificates (aka X509) was clashing with Certificate from StosSign
import Foundation
import SwiftASN1
import X509
import CryptoKit
import _CryptoExtras

public class CSR {
    public static func generateCSR() throws -> (data: Data?, pkey: Data?) {
        let subject = try DistinguishedName([
            .init(type: .NameAttributes.commonName, utf8String: "StosSign"),
            .init(type: .NameAttributes.organizationName, utf8String: "StosSign"),
            .init(type: .NameAttributes.countryName, printableString: "US"),
            .init(type: .NameAttributes.stateOrProvinceName, utf8String: "CA"),
            .init(type: .NameAttributes.localityName, utf8String: "Los Angeles"),
        ])
        
        let privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        
        let privateKeyCertificate = Certificate.PrivateKey(privateKey)
        let extensions = try Certificate.Extensions {
            //SubjectAlternativeNames([.dnsName("YOUR_DNS_NAME")])
        }
        let extensionRequest = ExtensionRequest(extensions: extensions)
        let attributes = try CertificateSigningRequest.Attributes(
            [.init(extensionRequest)]
        )
        let csr = try CertificateSigningRequest(version: .v1, subject: subject, privateKey: privateKeyCertificate, attributes: attributes, signatureAlgorithm: .sha256WithRSAEncryption)
        
        if !csr.publicKey.isValidSignature(csr.signature, for: csr) {
            throw NSError(domain: "StosSign_CSR", code: 1)
        }
        
        let csrBytex = try csr.serializeAsPEM(discriminator: CertificateSigningRequest.defaultPEMDiscriminator).derBytes
        
        let csrData = Data(csrBytex)
        
        return (data: csrData, pkey: privateKey.pemRepresentation.data(using: .utf8))
    }
}
