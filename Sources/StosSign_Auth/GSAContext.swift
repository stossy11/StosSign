//
//  GSAContext.swift
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//

import Foundation
import CryptoSwift
import Crypto
import SRP

public final class GSAContext {
    public let username: String
    public let password: String
    public var salt: Data?
    public var serverPublicKey: Data?
    public var sessionKey: Data?
    public var dsid: String?
    
    private(set) var publicKey: Data?
    private(set) var verificationMessage: Data?
    
    private var clientKeys: SRPKeyPair?
    private let configuration = SRPConfiguration<SHA256>(.N2048)
    private lazy var client = SRPClient(configuration: configuration)
    var isHexdecimal = false
    
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
    
    public func start() -> Data? {
        guard publicKey == nil else { return nil }
        
        clientKeys = client.generateKeys()
        publicKey = Data(clientKeys?.public.bytes ?? [])
        return publicKey
    }
    
    public func makeVerificationMessage(iterations: Int = 50_000, isHexadecimal: Bool) -> Data? {
        self.isHexdecimal = isHexadecimal
        guard verificationMessage == nil,
              let salt = salt,
              let serverPublicKeyData = serverPublicKey,
              let clientKeys = clientKeys else { return nil }
        
        let serverPublicKey = SRPKey(serverPublicKeyData.bytes)
        
        guard let x = makeAppleX(password: password, salt: salt, iterations: iterations) else {
            return nil
        }
        
        do {
            let sharedSecret = try client.calculateSharedSecret(
                // username: username,
                password: x.bytes,
                salt: salt.bytes,
                clientKeys: clientKeys,
                serverPublicKey: serverPublicKey
            )
            
            sessionKey = Data(sharedSecret.bytes)
            
            let clientProof = client.calculateClientProof(
                // username: username,
                salt: salt.bytes,
                clientPublicKey: clientKeys.public,
                serverPublicKey: serverPublicKey,
                sharedSecret: sharedSecret
            )
            
            verificationMessage = Data(clientProof)
            return verificationMessage
            
        } catch {
            print("SRP Error: \(error)")
            return nil
        }
    }
    
    public func verifyServerVerificationMessage(_ serverProof: Data) -> Bool {
        guard !serverProof.isEmpty,
              let clientKeys = clientKeys,
              let sessionKey = sessionKey,
              let clientProof = verificationMessage else { return false }
        
        do {
            try client.verifyServerProof(
                serverProof: serverProof.bytes,
                clientProof: clientProof.bytes,
                clientPublicKey: clientKeys.public,
                sharedSecret: SRPKey(sessionKey.bytes)
            )
            return true
        } catch {
            print("Server proof verification failed: \(error)")
            return false
        }
    }
    
    private func makeAppleX(password: String, salt: Data, iterations: Int) -> Data? {
        let passwordData = Data(password.utf8)
        let digest = SHA256.hash(data: passwordData)
        
        let inputForPBKDF2: [UInt8]
        if self.isHexdecimal {
            inputForPBKDF2 = Array(digest).toHexString().bytes
        } else {
            inputForPBKDF2 = Array(digest)
        }

        do {
            let kdf = try PKCS5.PBKDF2(
                password: inputForPBKDF2,
                salt: Array(salt),
                iterations: iterations,
                keyLength: 32,
                variant: .sha2(.sha256)
            )
            let derivedKey = try kdf.calculate()
            
            return Data(derivedKey)
        } catch {
            print("KDF Calculation failed: \(error)")
            return nil
        }
    }
    
    public func makeChecksum(appName: String) -> Data? {
        guard let sessionKey = sessionKey, let dsid = dsid else { return nil }
        
        let key = SymmetricKey(data: sessionKey)
        var hmac = HMAC<SHA256>(key: key)
        
        for string in ["apptokens", dsid, appName] {
            hmac.update(data: Data(string.utf8))
        }
        
        return Data(hmac.finalize())
    }
    
    internal func makeHMACKey(_ string: String) -> Data {
        guard let sessionKey = sessionKey else { return Data() }
        let key = SymmetricKey(data: sessionKey)
        var hmac = HMAC<SHA256>(key: key)
        hmac.update(data: Data(string.utf8))
        return Data(hmac.finalize())
    }
}

extension Data {
    func hexadecimal() -> String {
        map { String(format: "%02hhx", $0) }.joined()
    }
    
    public func decryptedCBC(context gsaContext: GSAContext) -> Data? {
         let sessionKey = gsaContext.makeHMACKey("extra data key:")
         var iv = gsaContext.makeHMACKey("extra data iv:")
         iv = iv.count >= 16 ? iv.prefix(16) : iv
         
         do {
             let cipher = try AESCipher(key: sessionKey.bytes, iv: iv.bytes)
             let decrypted = try cipher.decrypt(bytes: self.bytes)
             return Data(decrypted)
         } catch {
             print("AES-CBC decryption failed: \(error)")
             return nil
         }
     }
     
    
    public func decryptedGCM(context gsaContext: GSAContext) -> Data? {
        guard let sessionKey = gsaContext.sessionKey, count >= 35 else { return nil }
        
        let version = self[0..<3]
        let iv = self[3..<19]
        let ciphertext = self[19..<count-16]
        let tag = self.suffix(16)
        
        do {
            let nonce = try AES.GCM.Nonce(data: iv)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            let key = SymmetricKey(data: sessionKey)
            return try AES.GCM.open(sealedBox, using: key, authenticating: version)
        } catch {
            return nil
        }
    }
    
    var bytes: [UInt8] {
        return Array(self)
    }
}

extension SRPClient {
    public func calculateClientProof(
        // username: String,
        salt: [UInt8],
        clientPublicKey: SRPKey,
        serverPublicKey: SRPKey,
        sharedSecret: SRPKey
    ) -> [UInt8] {
        let clientPublicKey = clientPublicKey.with(padding: configuration.sizeN)
        let serverPublicKey = serverPublicKey.with(padding: configuration.sizeN)
        let sharedSecret = sharedSecret.with(padding: configuration.sizeN)
        let hashSharedSecret = [UInt8](H.hash(data: sharedSecret.bytes))
        // get verification code
        return SRP<H>.calculateClientProof(
            configuration: configuration,
            // username: username,
            salt: salt,
            clientPublicKey: clientPublicKey,
            serverPublicKey: serverPublicKey,
            hashSharedSecret: hashSharedSecret
        )
    }
}

extension SRP {
    static func calculateClientProof(
        configuration: SRPConfiguration<H>,
        salt: [UInt8],
        clientPublicKey: SRPKey,
        serverPublicKey: SRPKey,
        hashSharedSecret: [UInt8]
    ) -> [UInt8] {
        let hashN = [UInt8](H.hash(data: configuration.N.bytes))
        let hashG = [UInt8](H.hash(data: configuration.g.bytes.pad(to: configuration.sizeN)))
        
        let N_xor_g = zip(hashN, hashG).map { $0 ^ $1 }
        
        let M1 = N_xor_g + salt
        
        let M2 = clientPublicKey.bytes + serverPublicKey.bytes + hashSharedSecret
        
        let M = H.hash(data: M1 + M2)
        return [UInt8](M)
    }
}

extension Crypto.Digest {
    func hexadecimal() -> String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}


extension Array where Element == UInt8 {
    func pad(to size: Int) -> [UInt8] {
        let padSize = size - count
        guard padSize > 0 else { return self }
        // create prefix and return prefix + data
        let prefix: [UInt8] = (1 ... padSize).reduce([]) { result, _ in result + [0] }
        return prefix + self
    }
}
