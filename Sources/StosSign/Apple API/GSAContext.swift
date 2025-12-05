//
//  GSAContext.swift
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//


import Foundation
import Crypto
import CommonCrypto
import StosCSRP

public final class GSAContext {
    public let username: String
    public let password: String
    public var salt: Data?
    public var serverPublicKey: Data?
    public var sessionKey: Data?
    public var dsid: String?
    
    private(set) var publicKey: Data?
    private(set) var derivedPasswordKey: Data?
    private(set) var verificationMessage: Data?
    
    private var srpUser: OpaquePointer?
    private let algorithm: SRP_HashAlgorithm = SRP_SHA256
    private let ngType: SRP_NGType = SRP_NG_2048
    
    init(username: String, password: String) {
        self.username = username
        self.password = password
    }
    
    deinit {
        if let user = srpUser {
            srp_user_delete(user)
        }
    }
    
    func start() -> Data? {
        guard publicKey == nil else { return nil }
        
        srpUser = srp_user_new(
            algorithm,
            ngType,
            username,
            password.data(using: .utf8)!.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: UInt8.self) },
            Int32(password.utf8.count),
            nil,
            nil
        )
        
        guard let user = srpUser else { return nil }
        
        var authUsername: UnsafePointer<CChar>?
        var bytesA: UnsafePointer<UInt8>?
        var lenA: Int32 = 0
        
        srp_user_start_authentication(user, &authUsername, &bytesA, &lenA)
        
        guard let bytes = bytesA, lenA > 0 else { return nil }
        publicKey = Data(bytes: bytes, count: Int(lenA))
        
        return publicKey
    }
    
    func makeVerificationMessage(iterations: Int, isHexadecimal: Bool) -> Data? {
        guard verificationMessage == nil,
              let salt = salt,
              let serverPublicKey = serverPublicKey,
              let user = srpUser else { return nil }
        
        guard let derivedPasswordKey = makeX(
            password: password,
            salt: salt,
            iterations: iterations,
            isHexadecimal: isHexadecimal
        ) else { return nil }
        
        self.derivedPasswordKey = derivedPasswordKey
        
        var bytesM: UnsafePointer<UInt8>?
        var lenM: Int32 = 0
        
        salt.withUnsafeBytes { saltBytes in
            serverPublicKey.withUnsafeBytes { bBytes in
                srp_user_process_challenge(
                    user,
                    saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    Int32(salt.count),
                    bBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    Int32(serverPublicKey.count),
                    &bytesM,
                    &lenM
                )
            }
        }
        
        guard let m = bytesM, lenM > 0 else { return nil }
        verificationMessage = Data(bytes: m, count: Int(lenM))
        
        let keyLength = srp_user_get_session_key_length(user)
        if keyLength > 0 {
            let keyBytes = srp_user_get_session_key(user, nil)
            if let key = keyBytes {
                sessionKey = Data(bytes: key, count: Int(keyLength))
            }
        }
        
        return verificationMessage
    }
    
    func verifyServerVerificationMessage(_ serverVerificationMessage: Data) -> Bool {
        guard !serverVerificationMessage.isEmpty,
              let user = srpUser else { return false }
        
        serverVerificationMessage.withUnsafeBytes { bytes in
            srp_user_verify_session(
                user,
                bytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            )
        }
        
        return srp_user_is_authenticated(user) != 0
    }
    
    func makeChecksum(appName: String) -> Data? {
        guard let sessionKey = sessionKey, let dsid = dsid else { return nil }
        
        let key = SymmetricKey(data: sessionKey)
        var hmac = HMAC<SHA256>.init(key: key)
        
        for string in ["apptokens", dsid, appName] {
            hmac.update(data: Data(string.utf8))
        }
        
        return Data(hmac.finalize())
    }

    internal func makeHMACKey(_ string: String) -> Data {
        guard let sessionKey = sessionKey else { return Data() }
        
        let key = SymmetricKey(data: sessionKey)
        var hmac = HMAC<SHA256>.init(key: key)
        hmac.update(data: Data(string.utf8))
        
        return Data(hmac.finalize())
    }
    
    private func makeX(
        password: String,
        salt: Data,
        iterations: Int,
        isHexadecimal: Bool
    ) -> Data? {
        let passwordData = Data(password.utf8)
        var digest = SHA256.hash(data: passwordData)
        
        let processedDigest: Data
        if isHexadecimal {
            processedDigest = Data(digest.hexadecimal().utf8)
        } else {
            processedDigest = Data(digest)
        }
        
        var derivedKey = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            processedDigest.withUnsafeBytes { digestBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        digestBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        processedDigest.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Int(CC_SHA256_DIGEST_LENGTH)
                    )
                }
            }
        }
        
        return result == kCCSuccess ? derivedKey : nil
    }
}

extension Data {
    func hexadecimal() -> String {
        map { String(format: "%02hhx", $0) }.joined()
    }
    
    func decryptedCBC(context gsaContext: GSAContext) -> Data? {
        let sessionKey = gsaContext.makeHMACKey("extra data key:")
        let iv = gsaContext.makeHMACKey("extra data iv:")
        
        let decryptedSize = self.count + kCCBlockSizeAES128
        var decryptedData = Data(count: decryptedSize)
        var numBytesDecrypted: size_t = 0
        
        let cryptStatus = decryptedData.withUnsafeMutableBytes { decryptedBytes in
            self.withUnsafeBytes { encryptedBytes in
                sessionKey.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            sessionKey.count,
                            ivBytes.baseAddress,
                            encryptedBytes.baseAddress,
                            self.count,
                            decryptedBytes.baseAddress,
                            decryptedSize,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else { return nil }
        decryptedData.count = numBytesDecrypted
        return decryptedData
    }
    
    func decryptedGCM(context gsaContext: GSAContext) -> Data? {
        guard let sessionKey = gsaContext.sessionKey else { return nil }
        
        let versionSize = 3
        let ivSize = 16
        let tagSize = 16
        
        let decryptedSize = count - (versionSize + ivSize + tagSize)
        guard decryptedSize > 0 else { return nil }
        
        let version = self[0..<versionSize]
        let iv = self[versionSize..<versionSize + ivSize]
        let ciphertext = self[versionSize + ivSize..<count - tagSize]
        let tag = self[count - tagSize..<count]
        
        do {
            let nonce = try AES.GCM.Nonce(data: iv)
            let sealedBox = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: ciphertext,
                tag: tag
            )
            
            let key = SymmetricKey(data: sessionKey)
            let decryptedData = try AES.GCM.open(sealedBox, using: key, authenticating: version)
            
            return decryptedData
        } catch {
            return nil
        }
    }
}

extension Digest {
    func hexadecimal() -> String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}
