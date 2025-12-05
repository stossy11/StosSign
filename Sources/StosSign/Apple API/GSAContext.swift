//
//  GSAContext.swift
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//


import Foundation
import Crypto
import CommonCrypto
import SRP
import BigInt

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
    private var privateKey: Data?
    
    private var clientKeys: SRPKeyPair?
    private let configuration = SRPConfiguration<SHA256>(.N2048)
    private lazy var client = SRPClient(configuration: configuration)
    
    // SRP-6a constants for N2048
    private let N = BigUInt("AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DDB1F0E39FE5EE71DFF8F2B4C00C6AA7F0C5E5E3BE5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B5C0C3E5E3C0C3B", radix: 16)!
    private let g = BigUInt(2)
    
    init(username: String, password: String) {
        self.username = username
        self.password = password
    }
    
    func start() -> Data? {
        guard publicKey == nil else { return nil }
        
        clientKeys = client.generateKeys()
        publicKey = Data(clientKeys?.public.bytes ?? [])
        privateKey = Data(clientKeys?.private.bytes ?? [])
        
        return publicKey
    }
    
    func makeVerificationMessage(iterations: Int, isHexadecimal: Bool) -> Data? {
        print("Starting verification message creation")
        
        guard verificationMessage == nil,
              let salt = salt,
              let serverPublicKeyData = serverPublicKey,
              let clientPublicKey = publicKey,
              let clientPrivateKey = privateKey else {
            print("Missing required data")
            return nil
        }
        
        print("Salt: \(salt.hexadecimal())")
        print("Iterations: \(iterations)")
        print("Hexadecimal mode: \(isHexadecimal)")
        print("Username: \(username)")
        print("Client public key (A): \(clientPublicKey.hexadecimal().prefix(64))...")
        print("Server public key (B): \(serverPublicKeyData.hexadecimal().prefix(64))...")
        
        // Step 1: Derive x from password using Apple's custom PBKDF2
        guard let derivedPasswordKey = makeX(
            password: password,
            salt: salt,
            iterations: iterations,
            isHexadecimal: isHexadecimal
        ) else {
            print("Failed to derive password key")
            return nil
        }
        
        self.derivedPasswordKey = derivedPasswordKey
        print("Derived key (x): \(derivedPasswordKey.hexadecimal())")
        
        // Step 2: Calculate u = H(A | B)
        var uData = Data()
        uData.append(clientPublicKey)
        uData.append(serverPublicKeyData)
        let uHash = SHA256.hash(data: uData)
        let u = BigUInt(Data(uHash))
        
        print("u: \(Data(uHash).hexadecimal())")
        
        // Step 3: Calculate k = H(N | g)
        let k = calculateSRPk()
        print("k: \(String(k, radix: 16).prefix(32))...")
        
        // Convert values to BigUInt
        let x = BigUInt(derivedPasswordKey)
        let a = BigUInt(clientPrivateKey)
        let A = BigUInt(clientPublicKey)
        let B = BigUInt(serverPublicKeyData)
        
        // Step 4: Validate B
        guard B % N != 0 else {
            print("Invalid server public key (B % N == 0)")
            return nil
        }
        
        // Step 5: Calculate S = (B - k * g^x) ^ (a + u * x) mod N
        let gx = g.power(x, modulus: N)
        let kgx = (k * gx) % N
        
        // Ensure positive subtraction: (B - kgx) mod N
        let BminusKgx: BigUInt
        if B >= kgx {
            BminusKgx = B - kgx
        } else {
            BminusKgx = B + N - kgx
        }
        
        // Calculate exponent: (a + u * x)
        let ux = u * x
        let exponent = a + ux
        
        // Calculate S = BminusKgx ^ exponent mod N
        let S = BminusKgx.power(exponent, modulus: N)
        
        // Step 6: Calculate session key K = H(S)
        let SData = Data(S.serialize())
        let K = SHA256.hash(data: SData)
        sessionKey = Data(K)
        
        print("Shared secret (S) length: \(SData.count) bytes")
        print("Shared secret (S): \(SData.hexadecimal().prefix(64))...")
        print("Session key (K): \(sessionKey!.hexadecimal())")
        
        // Step 7: Calculate M1 client proof
        let M1 = calculateClientProof(
            username: username,
            salt: salt,
            clientPublicKey: clientPublicKey,
            serverPublicKey: serverPublicKeyData,
            sessionKey: Data(K)
        )
        
        verificationMessage = M1
        print("Client proof (M1): \(M1.hexadecimal())")
        
        return verificationMessage
    }
    
    private func calculateSRPk() -> BigUInt {
        let NData = Data(N.serialize())
        var gData = Data(g.serialize())
        
        if gData.count < NData.count {
            let paddingCount = NData.count - gData.count
            gData = Data(repeating: 0, count: paddingCount) + gData
        }
        
        var kData = Data()
        kData.append(NData)
        kData.append(gData)
        
        let kHash = SHA256.hash(data: kData)
        return BigUInt(Data(kHash))
    }
    
    private func calculateClientProof(
        username: String,
        salt: Data,
        clientPublicKey: Data,
        serverPublicKey: Data,
        sessionKey: Data
    ) -> Data {
        let NData = Data(N.serialize())
        var gData = Data(g.serialize())
        
        if gData.count < NData.count {
            let paddingCount = NData.count - gData.count
            gData = Data(repeating: 0, count: paddingCount) + gData
        }
        
        let hashN = SHA256.hash(data: NData)
        let hashG = SHA256.hash(data: gData)


        let hashNBytes = Array(hashN)
        let hashGBytes = Array(hashG)

        var xorResult = Data(capacity: 32)
        for i in 0..<32 {
            xorResult.append(hashNBytes[i] ^ hashGBytes[i])
        }

        let hashUsername = SHA256.hash(data: Data(username.utf8))

        var m1Data = Data()
        m1Data.append(xorResult)
        m1Data.append(Data(hashUsername))
        m1Data.append(salt)
        m1Data.append(clientPublicKey)
        m1Data.append(serverPublicKey)
        m1Data.append(sessionKey)

        let m1Hash = SHA256.hash(data: m1Data)
        return Data(m1Hash)
    }

    func verifyServerVerificationMessage(_ serverVerificationMessage: Data) -> Bool {
        guard !serverVerificationMessage.isEmpty,
              let sharedSecret = sessionKey,
              let clientPublicKey = publicKey,
              let clientProof = verificationMessage else {
            return false
        }
        
        var m2Data = Data()
        m2Data.append(clientPublicKey)
        m2Data.append(clientProof)
        m2Data.append(sharedSecret)
        
        let expectedM2 = SHA256.hash(data: m2Data)
        let receivedM2 = serverVerificationMessage
        
        let isValid = Data(expectedM2) == receivedM2
        print(isValid ? "Server verification successful" : "Server verification failed")
        
        return isValid
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
        let digest = SHA256.hash(data: passwordData)
        
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
