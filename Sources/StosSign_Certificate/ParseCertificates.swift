//
//  ParseCertificates.swift
//  StosSign
//
//  Created by Stossy11 on 09/12/2025.
//

import Foundation
import X509
import CryptoKit

public class CertificateParser {
    public static func parseCerts(_ cert: Data) -> (String, String)? {
        do {
            let bytes = [UInt8](cert)
            let certificate = try Certificate(derEncoded: bytes)
            let serial = String(data: Data(certificate.serialNumber.bytes), encoding: .utf8) ?? ""
            for name in certificate.subject {
                print(name)
            }
            
            return ("", serial)
        } catch {
            return nil
        }
    }
}
