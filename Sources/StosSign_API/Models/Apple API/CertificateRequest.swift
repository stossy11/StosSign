//
//  CertificateRequest.swift
//  StosSign
//
//  Created by Stossy11 on 19/03/2025.
//

import Foundation
import StosOpenSSL
import StosSign_Certificate

public class CertificateRequest {
    public static func generate() -> (csr: Data?, privateKey: Data?)? {
        do {
            let (csrData, privateKeyData) = try CSR.generateCSR()
            
            return (csrData, privateKeyData)
        } catch {
            return nil
        }
    }
}

