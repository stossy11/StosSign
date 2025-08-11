//
//  GSAContext.swift
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//


import Foundation
import CommonCrypto
import CoreCrypto
#if os(macOS) || os(iOS)
import UIKit
#endif

public func ccdigest_ctx_size(_ stateSize: Int, _ blockSize: Int) -> Int {
    stateSize + MemoryLayout<UInt64>.size + blockSize + MemoryLayout<UInt32>.size
}

public func ccdigest_di_size(_ digestInfo: UnsafePointer<ccdigest_info>) -> Int {
    ccdigest_ctx_size(digestInfo.pointee.state_size, digestInfo.pointee.block_size)
}

public func ccsrp_gpbuf_size(_ group: ccdh_const_gp_t) -> Int {
    ccdh_ccn_size(group) * 4
}

public func ccsrp_dibuf_size(_ digestInfo: UnsafePointer<ccdigest_info>) -> Int {
    digestInfo.pointee.output_size * 4
}

public func ccsrp_sizeof_srp(_ digestInfo: UnsafePointer<ccdigest_info>, _ group: ccdh_const_gp_t) -> Int {
    MemoryLayout<ccsrp_ctx>.size + ccsrp_gpbuf_size(group) + ccsrp_dibuf_size(digestInfo)
}

public func cchmac_ctx_size(_ stateSize: Int, _ blockSize: Int) -> Int {
    ccdigest_ctx_size(stateSize, blockSize) + stateSize
}

public func cchmac_di_size(_ digestInfo: UnsafePointer<ccdigest_info>) -> Int {
    let baseSize = cchmac_ctx_size(digestInfo.pointee.state_size, digestInfo.pointee.block_size)
    #if os(iOS) || os(macOS)
    let systemVersion = UIDevice.current.systemVersion
    let majorVersion = Int(systemVersion.components(separatedBy: ".").first ?? "0") ?? 0
    
    switch UIDevice.current.systemName {
    case "iOS" where majorVersion >= 14:
        return baseSize * 2
    case "macOS" where majorVersion >= 11:
        return baseSize * 2
    default:
        return baseSize
    }
    #else
    return baseSize
    #endif
}

public class GSAContext {
    public let username: String
    public let password: String
    public var salt: Data?
    public var serverPublicKey: Data?
    public var sessionKey: Data?
    public var dsid: String?
    
    private(set) var publicKey: Data?
    private(set) var derivedPasswordKey: Data?
    private(set) var verificationMessage: Data?
    
    private let srpGroup = ccsrp_gp_rfc5054_2048()!
    private let digestInfo = ccsha256_di()!
    
    private lazy var srpContext: ccsrp_ctx_t = {
        let size = ccsrp_sizeof_srp(self.digestInfo, self.srpGroup)
        let context = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: MemoryLayout<UInt8>.alignment).assumingMemoryBound(to: ccsrp_ctx.self)
        ccsrp_ctx_init(context, self.digestInfo, self.srpGroup)
        ccsrp_client_set_noUsernameInX(context, true)
        context.pointee.blinding_rng = ccrng(nil)
        return context
    }()
    
    init(username: String, password: String) {
        self.username = username
        self.password = password
    }
    
    func start() -> Data? {
        guard publicKey == nil else { return nil }
        publicKey = makeAKey()
        return publicKey
    }
    
    func makeVerificationMessage(iterations: Int, isHexadecimal: Bool) -> Data? {
        guard verificationMessage == nil,
              let salt = salt,
              let serverPublicKey = serverPublicKey else { return nil }
        
        guard let derivedPasswordKey = makeX(
            password: password,
            salt: salt,
            iterations: iterations,
            isHexadecimal: isHexadecimal
        ) else { return nil }
        
        self.derivedPasswordKey = derivedPasswordKey
        verificationMessage = makeM1(
            username: username,
            derivedPasswordKey: derivedPasswordKey,
            salt: salt,
            serverPublicKey: serverPublicKey
        )
        
        return verificationMessage
    }
    
    func verifyServerVerificationMessage(_ serverVerificationMessage: Data) -> Bool {
        guard !serverVerificationMessage.isEmpty else { return false }
        
        return serverVerificationMessage.withUnsafeBytes { bytes in
            let pointer = bytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return ccsrp_client_verify_session(self.srpContext, pointer)
        }
    }
    
    func makeChecksum(appName: String) -> Data? {
        guard let sessionKey = sessionKey, let dsid = dsid else { return nil }
        
        var context = CCHmacContext()
        let algorithm = CCHmacAlgorithm(kCCHmacAlgSHA256)
        
        sessionKey.withUnsafeBytes { keyBytes in
            CCHmacInit(&context, algorithm, keyBytes.baseAddress, sessionKey.count)
        }
        
        for string in ["apptokens", dsid, appName] {
            string.withCString { cString in
                CCHmacUpdate(&context, cString, strlen(cString))
            }
        }
        
        var checksum = Data(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        checksum.withUnsafeMutableBytes { outputBytes in
            CCHmacFinal(&context, outputBytes.baseAddress)
        }
        
        return checksum
    }

    internal func makeHMACKey(_ string: String) -> Data {
        
        var keySize = 0
        let rawSessionKey = ccsrp_get_session_key(srpContext, &keySize)
        
        var sessionKey = Data(repeating: 0, count: keySize)
        sessionKey.withUnsafeMutableBytes { sessionKeyBytes in
            string.withCString { cString in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), rawSessionKey, keySize, cString, strlen(cString), sessionKeyBytes.baseAddress)
            }
        }
        
        return sessionKey
    }
    
    private func makeAKey() -> Data? {
        let size = ccsrp_exchange_size(srpContext)
        var keyA = Data(repeating: 0, count: size)
        
        let result = keyA.withUnsafeMutableBytes {
            ccsrp_client_start_authentication(srpContext, ccrng(nil), $0.baseAddress!)
        }
        
        return result == 0 ? keyA : nil
    }
    
    private func makeX(
        password: String,
        salt: Data,
        iterations: Int,
        isHexadecimal: Bool
    ) -> Data? {
        var digest = Data(repeating: 0, count: digestInfo.pointee.output_size)
        digest.withUnsafeMutableBytes {
            ccdigest(digestInfo, password.utf8.count, password, $0.baseAddress!)
        }
        
        let digestLength = isHexadecimal ?
            digestInfo.pointee.output_size * 2 :
            digestInfo.pointee.output_size
        
        let processedDigest = isHexadecimal ? digest.hexadecimal() : digest
        
        var x = Data(repeating: 0, count: digestInfo.pointee.output_size)
        
        let result = x.withUnsafeMutableBytes { xBytes in
            processedDigest.withUnsafeBytes { digestBytes in
                salt.withUnsafeBytes { saltBytes in
                    ccpbkdf2_hmac(
                        digestInfo,
                        digestLength,
                        digestBytes.baseAddress,
                        salt.count,
                        saltBytes.baseAddress,
                        iterations,
                        digestInfo.pointee.output_size,
                        xBytes.baseAddress
                    )
                }
            }
        }
        
        return result == 0 ? x : nil
    }
    
    private func makeM1(
        username: String,
        derivedPasswordKey x: Data,
        salt: Data,
        serverPublicKey B: Data
    ) -> Data? {
        let size = ccsrp_get_session_key_length(srpContext)
        var M1 = Data(repeating: 0, count: size)
        
        let result = M1.withUnsafeMutableBytes { m1Bytes in
            x.withUnsafeBytes { xBytes in
                salt.withUnsafeBytes { saltBytes in
                    B.withUnsafeBytes { bBytes in
                        ccsrp_client_process_challenge(
                            srpContext,
                            username,
                            xBytes.count,
                            xBytes.baseAddress!,
                            salt.count,
                            saltBytes.baseAddress!,
                            bBytes.baseAddress!,
                            m1Bytes.baseAddress!
                        )
                    }
                }
            }
        }
        
        return result == 0 ? M1 : nil
    }
}

extension Data {
    static func makeBuffer<T>(size: Int, type: T.Type) -> UnsafeMutablePointer<T> {
        UnsafeMutableRawPointer.allocate(
            byteCount: size,
            alignment: MemoryLayout<UInt8>.alignment
        ).assumingMemoryBound(to: type)
    }
    
    func hexadecimal() -> Data {
        let hexString = map { String(format: "%02hhx", $0) }.joined()
        return Data(hexString.flatMap { $0.utf8.map { UInt8($0) } })
    }
    
    func decryptedCBC(context gsaContext: GSAContext) -> Data? {
        guard let mode = ccaes_cbc_decrypt_mode() else { return nil }
        
        let context = Data.makeBuffer(size: mode.pointee.size, type: cccbc_ctx.self)
        defer { context.deallocate() }
        
        let sessionKey = gsaContext.makeHMACKey("extra data key:")
        _ = sessionKey.withUnsafeBytes {
            mode.pointee.`init`(mode, context, sessionKey.count, $0.baseAddress)
        }
        
        var initializationVector = gsaContext.makeHMACKey("extra data iv:")
        var decryptedData = Data(repeating: 0, count: count)
        
        let size = decryptedData.withUnsafeMutableBytes { decryptedBytes in
            self.withUnsafeBytes { dataBytes in
                initializationVector.withUnsafeMutableBytes { ivBytes -> size_t in
                    let ivPointer = ivBytes.baseAddress!.assumingMemoryBound(to: cccbc_iv.self)
                    return ccpad_pkcs7_decrypt(
                        mode,
                        context,
                        ivPointer,
                        self.count,
                        dataBytes.baseAddress,
                        decryptedBytes.baseAddress
                    )
                }
            }
        }
        
        guard size <= count else { return nil }
        return decryptedData
    }
    
    func decryptedGCM(context gsaContext: GSAContext) -> Data? {
        guard let mode = ccaes_gcm_decrypt_mode(),
              let sessionKey = gsaContext.sessionKey else { return nil }
        
        let context = Data.makeBuffer(size: mode.pointee.size, type: ccgcm_ctx.self)
        defer { context.deallocate() }
        
        _ = sessionKey.withUnsafeBytes {
            mode.pointee.`init`(mode, context, sessionKey.count, $0.baseAddress!)
        }
        
        let versionSize = 3
        let ivSize = 16
        let tagSize = 16
        
        let decryptedSize = count - (versionSize + ivSize + tagSize)
        guard decryptedSize > 0 else { return nil }
        
        let version = self[0 ..< versionSize]
        let initializationVector = self[versionSize ..< versionSize + ivSize]
        let ciphertext = dropFirst(versionSize + ivSize).dropLast(tagSize)
        let tag = self[endIndex - tagSize ..< endIndex]
        
        _ = initializationVector.withUnsafeBytes {
            mode.pointee.set_iv(context, ivSize, $0.baseAddress)
        }
        
        _ = version.withUnsafeBytes {
            mode.pointee.gmac(context, version.count, $0.baseAddress)
        }
        
        var decryptedData = Data(repeating: 0, count: decryptedSize)
        _ = ciphertext.withUnsafeBytes { ciphertextBytes in
            decryptedData.withUnsafeMutableBytes { decryptedBytes in
                mode.pointee.gcm(
                    context,
                    decryptedSize,
                    ciphertextBytes.baseAddress,
                    decryptedBytes.baseAddress
                )
            }
        }
        
        var decryptedTag = Data(repeating: 0, count: tagSize)
        _ = decryptedTag.withUnsafeMutableBytes {
            mode.pointee.finalize(context, tagSize, $0.baseAddress)
        }
        
        guard tag == decryptedTag else { return nil }
        return decryptedData
    }
}
