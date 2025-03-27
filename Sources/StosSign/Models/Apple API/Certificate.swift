//
//  Certificate.swift
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//

import Foundation
import StosOpenSSL

public class Certificate {
    let name: String
    let serialNumber: String
    let data: Data?
    var privateKey: Data?
    var machineName: String?
    var machineIdentifier: String?
    var identifier: String?
    
    private static let pemPrefix = "-----BEGIN CERTIFICATE-----"
    private static let pemSuffix = "-----END CERTIFICATE-----"
    
    init(name: String, serialNumber: String, data: Data?) {
        self.name = name
        self.serialNumber = serialNumber
        self.data = data
    }
    
    convenience init?(p12Data: Data, password: String? = nil) {
        let passwordCString = password?.cString(using: .utf8)
        var certData: UnsafeMutablePointer<UInt8>? = nil
        var certLength: size_t = 0
        var keyData: UnsafeMutablePointer<UInt8>? = nil
        var keyLength: size_t = 0
        
        let success = p12Data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Bool in
            guard let baseAddress = bytes.baseAddress else { return false }
            return parse_p12_data(
                baseAddress.assumingMemoryBound(to: UInt8.self),
                Int32(p12Data.count),
                passwordCString,
                &certData,
                &certLength,
                &keyData,
                &keyLength
            )
        }
        
        guard success else { return nil }
        
        let pemData = Data(bytes: certData!, count: certLength)
        let privateKeyData = Data(bytes: keyData!, count: keyLength)
        
        free(certData)
        free(keyData)
        
        self.init(data: pemData)
        self.privateKey = privateKeyData
    }
    
    convenience init?(data: Data) {
        var name: UnsafeMutablePointer<CChar>? = nil
        var nameLength: size_t = 0
        var serialNumber: UnsafeMutablePointer<CChar>? = nil
        var serialNumberLength: size_t = 0
        
        let success = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Bool in
            guard let baseAddress = bytes.baseAddress else { return false }
            return parse_certificate_data(
                baseAddress.assumingMemoryBound(to: UInt8.self),
                Int32(data.count),
                &name,
                &nameLength,
                &serialNumber,
                &serialNumberLength
            )
        }
        
        guard success else { return nil }
        
        let nameString = String(cString: name!)
        let serialNumberString = String(cString: serialNumber!)
        
        free(name)
        free(serialNumber)
        
        self.init(name: nameString, serialNumber: serialNumberString, data: data)
    }
    
    convenience init?(responseDictionary: [String: Any]) {
        let identifier = responseDictionary["id"] as? String
        
        let attributesDictionary = responseDictionary["attributes"] as? [String: Any] ?? responseDictionary
        
        var data: Data? = nil
        if let certContent = attributesDictionary["certContent"] as? Data {
            data = certContent
        } else if let encodedData = attributesDictionary["certificateContent"] as? String {
            data = Data(base64Encoded: encodedData)
        }
        
        var machineName = attributesDictionary["machineName"] as? String
        
        var machineIdentifier = attributesDictionary["machineId"] as? String
        
        if let certData = data {
            self.init(data: certData)
        } else {
            let name = attributesDictionary["name"] as? String ?? ""
            let serialNumber = (attributesDictionary["serialNumber"] as? String) ??
                              (attributesDictionary["serialNum"] as? String) ?? ""
            
            self.init(name: name, serialNumber: serialNumber, data: nil)
        }
        
        self.machineName = machineName
        self.machineIdentifier = machineIdentifier
        self.identifier = identifier
    }
    
    var p12Data: Data? {
        return encryptedP12Data(password: "")
    }
    
    func encryptedP12Data(password: String) -> Data? {
        guard let certData = self.data, let privateKeyData = self.privateKey else {
            return nil
        }
        
        let passwordCString = password.cString(using: .utf8)
        var p12Data: UnsafeMutablePointer<UInt8>? = nil
        var p12Length: size_t = 0
        
        let success = certData.withUnsafeBytes { certBytes -> Bool in
            guard let certBaseAddress = certBytes.baseAddress else { return false }
            
            return privateKeyData.withUnsafeBytes { keyBytes -> Bool in
                guard let keyBaseAddress = keyBytes.baseAddress else { return false }
                
                return create_p12_data(
                    certBaseAddress.assumingMemoryBound(to: UInt8.self),
                    Int32(certData.count),
                    keyBaseAddress.assumingMemoryBound(to: UInt8.self),
                    Int32(privateKeyData.count),
                    passwordCString,
                    &p12Data,
                    &p12Length
                )
            }
        }
        
        guard success else { return nil }
        
        let resultData = Data(bytes: p12Data!, count: p12Length)
        
        // Free memory allocated by C function
        free(p12Data)
        
        return resultData
    }
    
    // MARK: - Equatable and Hashable
    static func == (lhs: Certificate, rhs: Certificate) -> Bool {
        return lhs.serialNumber == rhs.serialNumber
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(serialNumber)
    }
}

