//
//  Certificate.swift
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//

import Foundation
import StosOpenSSL
import os.log

// MARK: - Extensions
extension String {
    func chunked(into size: Int) -> [String] {
        return stride(from: 0, to: count, by: size).map {
            let start = index(startIndex, offsetBy: $0)
            let end = index(start, offsetBy: min(size, count - $0))
            return String(self[start..<end])
        }
    }
}

extension Data {
    var isPEM: Bool {
        guard let string = String(data: self, encoding: .utf8) else { return false }
        return string.contains("-----BEGIN CERTIFICATE-----") && string.contains("-----END CERTIFICATE-----")
    }
    
    var pemFormat: Data? {
        // If already PEM, return as is
        if isPEM { return self }
        
        // Convert DER to PEM
        let base64String = self.base64EncodedString()
        let pemString = "-----BEGIN CERTIFICATE-----\n" + 
                       base64String.chunked(into: 64).joined(separator: "\n") + 
                       "\n-----END CERTIFICATE-----"
        return pemString.data(using: .utf8)
    }
    
    var withoutComments: Data? {
        guard let string = String(data: self, encoding: .utf8) else { return self }
        
        // Remove comments (lines starting with #)
        let lines = string.components(separatedBy: .newlines)
        let filteredLines = lines.filter { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            return !trimmed.isEmpty && !trimmed.hasPrefix("#")
        }
        
        let cleanedString = filteredLines.joined(separator: "\n")
        return cleanedString.data(using: .utf8)
    }
}

public class Certificate: Equatable, Hashable {
    public let name: String
    public let serialNumber: String
    public var data: Data?
    public var p12Data: Data?
    public var privateKey: Data?
    public var machineName: String?
    public var machineIdentifier: String?
    public var identifier: String?
    
    private var cachedP12Data: Data?
    private var cachedP12Password: String?
    
    private static let logger = Logger(subsystem: "Certificate", category: "Operations")
    
    public init(name: String, serialNumber: String, data: Data? = nil) {
        self.name = name
        self.serialNumber = serialNumber
        self.data = data
        self.p12Data = encryptedP12Data(password: "")
        
        Self.logger.info("Certificate initialized - Name: \(name), Serial: \(serialNumber)")
    }
    
    public convenience init?(data certData: Data) {
        Self.logger.info("Initializing certificate from data (\(certData.count) bytes)")
        
        // Remove comments first
        guard let cleanData = certData.withoutComments else {
            Self.logger.error("Failed to clean certificate data")
            return nil
        }
        
        let finalData: Data
        
        if cleanData.isPEM {
            Self.logger.info("Data is already in PEM format")
            finalData = cleanData
            
            guard let pemString = String(data: cleanData, encoding: .utf8) else {
                Self.logger.error("Failed to convert PEM data to string")
                return nil
            }
            
            let lines = pemString.components(separatedBy: .newlines)
            let base64Lines = lines.filter { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return !trimmed.isEmpty && 
                       !trimmed.hasPrefix("-----BEGIN") && 
                       !trimmed.hasPrefix("-----END")
            }
            
            let base64String = base64Lines.joined()
            guard let derData = Data(base64Encoded: base64String) else {
                Self.logger.error("Failed to decode base64 from PEM")
                return nil
            }
            
            var name: UnsafeMutablePointer<CChar>?
            var nameLength: size_t = 0
            var serialNumber: UnsafeMutablePointer<CChar>?
            var serialNumberLength: size_t = 0
            
            let success = derData.withUnsafeBytes { bytes in
                guard let baseAddress = bytes.baseAddress else { return false }
                return parse_certificate_data(
                    baseAddress.assumingMemoryBound(to: UInt8.self),
                    Int32(derData.count),
                    &name,
                    &nameLength,
                    &serialNumber,
                    &serialNumberLength
                )
            }
            
            guard success,
                  let namePtr = name,
                  let serialPtr = serialNumber else {
                Self.logger.error("Failed to parse PEM certificate data with OpenSSL")
                return nil
            }
            
            let nameString = String(cString: namePtr)
            let serialNumberString = String(cString: serialPtr)
            
            free(name)
            free(serialNumber)
            
            Self.logger.info("Successfully parsed PEM certificate - Name: \(nameString), Serial: \(serialNumberString)")
            self.init(name: nameString, serialNumber: serialNumberString, data: finalData)
        } else {
            guard cleanData.first == 0x30 else {
                Self.logger.error("Invalid DER format: first byte is 0x\(String(format: "%02X", cleanData.first ?? 0)), expected 0x30")
                return nil
            }
            
            Self.logger.info("Converting DER to PEM format")
            
            var name: UnsafeMutablePointer<CChar>?
            var nameLength: size_t = 0
            var serialNumber: UnsafeMutablePointer<CChar>?
            var serialNumberLength: size_t = 0
            
            let success = cleanData.withUnsafeBytes { bytes in
                guard let baseAddress = bytes.baseAddress else { return false }
                return parse_certificate_data(
                    baseAddress.assumingMemoryBound(to: UInt8.self),
                    Int32(cleanData.count),
                    &name,
                    &nameLength,
                    &serialNumber,
                    &serialNumberLength
                )
            }
            
            guard success,
                  let namePtr = name,
                  let serialPtr = serialNumber else {
                Self.logger.error("Failed to parse certificate data with OpenSSL")
                return nil
            }
            
            let nameString = String(cString: namePtr)
            let serialNumberString = String(cString: serialPtr)
            
            free(name)
            free(serialNumber)
            
            guard let pemData = cleanData.pemFormat else {
                Self.logger.error("Failed to convert DER to PEM format")
                return nil
            }
            
            finalData = pemData
            Self.logger.info("Successfully converted DER to PEM and parsed certificate - Name: \(nameString), Serial: \(serialNumberString)")
            self.init(name: nameString, serialNumber: serialNumberString, data: finalData)
        }
    }
    
    public convenience init?(responseDictionary: [String: Any]) {
        Self.logger.info("Initializing certificate from response dictionary")
        
        let identifier = responseDictionary["id"] as? String ??
                        responseDictionary["certificateId"] as? String ??
                        responseDictionary["certRequestId"] as? String
        let attributes = responseDictionary["attributes"] as? [String: Any] ?? responseDictionary
        
        var certData: Data?
        if let content = attributes["certContent"] as? Data {
            certData = content
        } else if let encodedData = attributes["certificateContent"] as? String {
            // Clean the base64 string and decode
            let cleanedBase64 = encodedData.replacingOccurrences(of: "\n", with: "")
                                        .replacingOccurrences(of: "\r", with: "")
                                        .replacingOccurrences(of: " ", with: "")
            if let base64Data = Data(base64Encoded: cleanedBase64) {
                certData = base64Data
                Self.logger.info("Successfully decoded certificate data: \(base64Data.count) bytes")
            } else {
                Self.logger.error("Failed to decode base64 certificate content")
            }
        }
        
        let machineName = attributes["machineName"] as? String
        let machineIdentifier = attributes["machineId"] as? String
        
        if let data = certData, let certificate = Certificate(data: data) {
            Self.logger.info("Successfully parsed certificate from data")
            self.init(name: certificate.name, serialNumber: certificate.serialNumber, data: certificate.data)
            self.privateKey = certificate.privateKey
        } else {
            Self.logger.warning("Falling back to attributes parsing")
            let name = attributes["name"] as? String ?? 
                    attributes["displayName"] as? String ?? ""
            let serialNumber = (attributes["serialNumber"] as? String) ?? 
                            (attributes["serialNum"] as? String) ?? ""
            
            let finalData = certData?.withoutComments?.pemFormat
            self.init(name: name, serialNumber: serialNumber, data: finalData)
        }
        
        self.machineName = machineName
        self.machineIdentifier = machineIdentifier
        self.identifier = identifier
        
        if let finalData = self.data {
            Self.logger.info("✅ Certificate initialized with data: \(finalData.count) bytes")
        } else {
            Self.logger.warning("⚠️ Certificate initialized with nil data")
        }
    }
        
    
    public func encryptedP12Data(password: String) -> Data? {
        if let cached = cachedP12Data, cachedP12Password == password {
            return cached
        }
        
        guard let certData = data,
              let keyData = privateKey else {
            Self.logger.error("Cannot create P12: missing certificate data or private key")
            return nil
        }
        
        let result = createP12(certData: certData, keyData: keyData, password: password)

        print("Created P12 data with password: \(password)")
        print(p12Data?.count ?? 0)

        if let p12Data = result {
            cachedP12Data = p12Data
            cachedP12Password = password
        }

        
        return result
    }
    
    public func createP12(certData: Data, keyData: Data, password: String) -> Data? {
        let passwordCString = password.cString(using: .utf8)
        var p12Data: UnsafeMutablePointer<UInt8>?
        var p12Length: size_t = 0
        
        let success = certData.withUnsafeBytes { certBytes in
            guard let certBase = certBytes.baseAddress else { return false }
            return keyData.withUnsafeBytes { keyBytes in
                guard let keyBase = keyBytes.baseAddress else { return false }
                return create_p12_data(
                    certBase.assumingMemoryBound(to: UInt8.self),
                    Int32(certData.count),
                    keyBase.assumingMemoryBound(to: UInt8.self),
                    Int32(keyData.count),
                    passwordCString,
                    &p12Data,
                    &p12Length
                )
            }
        }
        
        guard success,
              let p12Pointer = p12Data,
              p12Length > 0 else {
            Self.logger.error("Failed to create P12 data")
            return nil
        }
        
        let result = Data(bytes: p12Pointer, count: p12Length)
        free(p12Data)
        
        return result
    }
    
    public func clearP12Cache() {
        cachedP12Data = nil
        cachedP12Password = nil
    }
    
    public static func == (lhs: Certificate, rhs: Certificate) -> Bool {
        return lhs.serialNumber == rhs.serialNumber
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(serialNumber)
    }
}