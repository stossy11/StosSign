//
//  Signing.swift
//  StosSign
//
//  Created by Stossy11 on 03/04/2025.
//

import Foundation
import StosOpenSSL
import ZSign
import Zip

typealias EVP_PKEY = OpaquePointer
typealias X509 = OpaquePointer
typealias BIO = OpaquePointer

let AppleRootCertificateData = """
-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
"UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
"""
let AppleWWDRCertificateData = """
-----BEGIN CERTIFICATE-----
MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi
MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw
bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg
Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB
cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ
BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ
C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW
BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj
+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b
5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A
0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS
VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j
BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG
AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh
MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js
MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw
EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH
Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA
HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK
XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7
bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC
NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza
UDSdlTs=
-----END CERTIFICATE-----
"""

let LegacyAppleWWDRCertificateData = """
-----BEGIN CERTIFICATE-----
MIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp
ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTEz
MDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVTMRMwEQYD
VQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3Bl
ciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0U3rOfGOA
YXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkVCBmsqtsq
Mu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8V25nNYB2
NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHld0WNUEi6
Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1qarunFjVg
0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGjgaYwgaMw
HQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQFMAMBAf8w
HwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcwJTAjoCGg
H4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/BAQDAgGG
MBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Zviz1smwv
j+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/Nw0Uwj6OD
Dc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJTleMa1s8
Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1VAKmuu0sw
ruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur+cmV6U/k
TecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxRpVzscYqC
tGwPDBUf
-----END CERTIFICATE-----
"""


func CertificatesContent(certificate: Certificate) -> Data {
    let certificateP12Data = certificate.p12Data
    
    let inputP12Buffer = BIO_new(BIO_s_mem())
    BIO_write(inputP12Buffer, certificateP12Data.bytes, Int32(certificateP12Data!.count))
    
    let inputP12 = d2i_PKCS12_bio(inputP12Buffer, nil)
    
    // Extract key + certificate from .p12
    var key: EVP_PKEY?
    var certificate: X509?
    PKCS12_parse(inputP12, "", &key, &certificate, nil)
    
    // Prepare certificate chain of trust
    let certificates = sk_X509_new(nil)
    
    let rootCertificateBuffer = BIO_new_mem_buf(AppleRootCertificateData, Int32(strlen(AppleRootCertificateData)))
    var wwdrCertificateBuffer: BIO?
    
    let issuerHash = X509_issuer_name_hash(certificate)
    if issuerHash == 0x817d2f7a {
        // Use legacy WWDR certificate
        wwdrCertificateBuffer = BIO_new_mem_buf(LegacyAppleWWDRCertificateData, Int32(strlen(LegacyAppleWWDRCertificateData)))
    } else {
        // Use latest WWDR certificate
        wwdrCertificateBuffer = BIO_new_mem_buf(AppleWWDRCertificateData, Int32(strlen(AppleWWDRCertificateData)))
    }
    
    let rootCertificate = PEM_read_bio_X509(rootCertificateBuffer, nil, nil, nil)
    if rootCertificate != nil {
        sk_X509_push(certificates, rootCertificate)
    }
    
    let wwdrCertificate = PEM_read_bio_X509(wwdrCertificateBuffer, nil, nil, nil)
    if wwdrCertificate != nil {
        sk_X509_push(certificates, wwdrCertificate)
    }
    
    // Create new .p12 in memory with private key and certificate chain
    var emptyCString = strdup("")
    defer { free(emptyCString) }
    let outputP12 = PKCS12_create(&emptyCString, &emptyCString, key, certificate, certificates, 0, 0, 0, 0, 0)
    
    let outputP12Buffer = BIO_new(BIO_s_mem())
    i2d_PKCS12_bio(outputP12Buffer, outputP12)
    
    var buffer: UnsafePointer<UInt8>? = nil
    let size = BIO_get_mem_ptr_bridge(outputP12Buffer, &buffer)

    if size > 0 && buffer != nil {
        let p12Data = Data(bytes: buffer!, count: Int(size))
    } else {
        // Handle error
        let p12Data = Data()
    }
    
    PKCS12_free(inputP12)
    PKCS12_free(outputP12)
    
    BIO_free(wwdrCertificateBuffer)
    BIO_free(rootCertificateBuffer)
    
    BIO_free(inputP12Buffer)
    BIO_free(outputP12Buffer)
    
    return Data()
}




public enum SigningError: LocalizedError {
    case missingAppBundle(underlyingError: Error)
    case invalidApp
    case missingProvisioningProfile(bundleIdentifier: String)
    case missingCertificate
    case signingFailed(component: String, details: String?)
    case fileOperationFailed(Error)
    case unknown(String)
    
    public var errorDescription: String? {
        switch self {
        case .missingAppBundle:
            return NSLocalizedString("Missing App Bundle", comment: "Error when app bundle cannot be found")
        case .invalidApp:
            return NSLocalizedString("Invalid Application", comment: "Error when app is invalid or corrupted")
        case .missingProvisioningProfile(let bundleIdentifier):
            return String(format: NSLocalizedString("Missing Provisioning Profile for '%@'", comment: "Error when provisioning profile is missing"), bundleIdentifier)
        case .missingCertificate:
            return NSLocalizedString("Missing Certificate", comment: "Error when certificate is missing")
        case .signingFailed(let component, _):
            return String(format: NSLocalizedString("Failed to Sign %@", comment: "Error when signing fails"), component)
        case .fileOperationFailed:
            return NSLocalizedString("File Operation Failed", comment: "Error when file operation fails")
        case .unknown:
            return NSLocalizedString("Unknown Error", comment: "Generic unknown error")
        }
    }
    
    public var failureReason: String? {
        switch self {
        case .missingAppBundle(let error):
            return String(format: NSLocalizedString("The app bundle could not be extracted or found: %@", comment: "Failure reason for missing app bundle"), error.localizedDescription)
        case .invalidApp:
            return NSLocalizedString("The application file is invalid or corrupted and cannot be signed.", comment: "Failure reason for invalid app")
        case .missingProvisioningProfile(let bundleIdentifier):
            return String(format: NSLocalizedString("No provisioning profile was found that matches the bundle identifier '%@'.", comment: "Failure reason for missing provisioning profile"), bundleIdentifier)
        case .missingCertificate:
            return NSLocalizedString("The certificate or private key is missing or invalid.", comment: "Failure reason for missing certificate")
        case .signingFailed(let component, let details):
            if let details = details {
                return String(format: NSLocalizedString("The signing process failed for %@: %@", comment: "Failure reason for signing failure with details"), component, details)
            }
            return String(format: NSLocalizedString("The signing process failed for %@.", comment: "Failure reason for signing failure"), component)
        case .fileOperationFailed(let error):
            return String(format: NSLocalizedString("A file operation failed: %@", comment: "Failure reason for file operation failure"), error.localizedDescription)
        case .unknown(let message):
            return message
        }
    }
    
    public var recoverySuggestion: String? {
        switch self {
        case .missingAppBundle:
            return NSLocalizedString("Ensure the IPA file is not corrupted and try again.", comment: "Recovery suggestion for missing app bundle")
        case .invalidApp:
            return NSLocalizedString("Verify the application file is a valid iOS app and try again.", comment: "Recovery suggestion for invalid app")
        case .missingProvisioningProfile:
            return NSLocalizedString("Add a provisioning profile that matches the app's bundle identifier.", comment: "Recovery suggestion for missing provisioning profile")
        case .missingCertificate:
            return NSLocalizedString("Ensure you have selected a valid certificate with a private key.", comment: "Recovery suggestion for missing certificate")
        case .signingFailed:
            return NSLocalizedString("Check your certificate and provisioning profile, then try again.", comment: "Recovery suggestion for signing failure")
        case .fileOperationFailed:
            return NSLocalizedString("Check file permissions and available disk space.", comment: "Recovery suggestion for file operation failure")
        case .unknown:
            return NSLocalizedString("Please try again or contact support if the problem persists.", comment: "Recovery suggestion for unknown error")
        }
    }
}

public final class Signer {
    public let team: Team
    public let certificate: Certificate
    
    public static func load() {
        OpenSSL_add_all_algorithms()
    }
    
    public init(team: Team, certificate: Certificate) {
        self.team = team
        self.certificate = certificate
    }
    
    public func signApp(at appURL: URL, provisioningProfiles profiles: [ProvisioningProfile], completionHandler: @escaping (Result<Void, SigningError>) -> Void) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        var ipaURL: URL?
        var appBundleURL: URL?
        
        let finish: (Result<Void, SigningError>) -> Void = { result in
            if let ipaURL = ipaURL {
                try? FileManager.default.removeItem(at: ipaURL.deletingLastPathComponent())
            }
            completionHandler(result)
        }
        
        // Extract IPA if needed
        if appURL.pathExtension.lowercased() == "ipa" {
            ipaURL = appURL
            let outputDirectoryURL = appURL.deletingLastPathComponent().appendingPathComponent(UUID().uuidString, isDirectory: true)
            
            do {
                try FileManager.default.createDirectory(at: outputDirectoryURL, withIntermediateDirectories: true)
                try Zip.unzipFile(appURL, destination: outputDirectoryURL, overwrite: true, password: nil)
                appBundleURL = outputDirectoryURL
            } catch {
                finish(.failure(.missingAppBundle(underlyingError: error)))
                return progress
            }
        } else {
            appBundleURL = appURL
        }
        
        guard let appBundleURL = appBundleURL, let application = Application(fileURL: appBundleURL) else {
            finish(.failure(.invalidApp))
            return progress
        }
        
        progress.totalUnitCount = Int64(FileManager.default.subpaths(atPath: appURL.path)?.count ?? 0)
        
        DispatchQueue.global(qos: .default).async {
            let profileForApp: (Application) -> ProvisioningProfile? = { app in
                profiles.first { profile in
                    let profileBID = profile.bundleIdentifier
                    let appBID = app.bundleIdentifier

                    let profilePrefix = profileBID?.split(separator: ".").dropLast().joined(separator: ".")
                    let appPrefix = appBID.split(separator: ".").dropLast().joined(separator: ".")

                    return profilePrefix == appPrefix
                }
            }
            
            let prepareApp: (Application) -> SigningError? = { app in
                guard let profile = profileForApp(app) else {
                    return .missingProvisioningProfile(bundleIdentifier: app.bundleIdentifier)
                }
                
                do {
                    try profile.data.write(to: app.fileURL.appendingPathComponent("embedded.mobileprovision"), options: .atomic)
                    return nil
                } catch {
                    return .fileOperationFailed(error)
                }
            }
            
            if let error = prepareApp(application) {
                finish(.failure(error))
                return
            }
            
            for appExtension in application.appExtensions {
                if let error = prepareApp(appExtension) {
                    finish(.failure(error))
                    return
                }
            }
            
            do {
                let key = CertificatesContent(certificate: self.certificate)
                let p12FilePath = URL.temporaryDirectory.appendingPathComponent("certificate.p12")
                try key.write(to: p12FilePath)
                
                guard let profile = profileForApp(application),
                      let provisioningPath = try? saveProvisioningProfile(profile),
                      let privateKey = self.certificate.privateKey else {
                    finish(.failure(.missingCertificate))
                    return
                }
                
                let privateKeyPath = URL.temporaryDirectory.appendingPathComponent("\(self.certificate.identifier ?? "").pem")
                try privateKey.write(to: privateKeyPath)
                
                // Sign app extensions
                for appExtension in application.appExtensions {
                    guard let extensionProfile = profileForApp(appExtension),
                          let extensionProvisioningPath = try? saveProvisioningProfile(extensionProfile) else {
                        finish(.failure(.missingProvisioningProfile(bundleIdentifier: appExtension.bundleIdentifier)))
                        return
                    }
                    
                    let extensionResult = zsign(appExtension.fileURL.path, p12FilePath.path, privateKeyPath.path, extensionProvisioningPath, "", appExtension.bundleIdentifier, appExtension.name)
                    
                    if extensionResult != 0 {
                        finish(.failure(.signingFailed(component: "app extension '\(appExtension.name)'", details: "zsign returned code \(extensionResult)")))
                        return
                    }
                }
                
                // Sign main application
                let result = zsign(appBundleURL.path, p12FilePath.path, privateKeyPath.path, provisioningPath, "", application.bundleIdentifier, application.name)
                
                if result != 0 {
                    finish(.failure(.signingFailed(component: "main application", details: "zsign returned code \(result)")))
                    return
                }
                
                // Repackage IPA if needed
                DispatchQueue.global(qos: .default).asyncAfter(deadline: .now() + 0.5) {
                    if let ipaURL = ipaURL {
                        do {
                            if FileManager.default.fileExists(atPath: ipaURL.path) {
                                try FileManager.default.removeItem(at: ipaURL)
                            }
                            try Zip.zipFiles(paths: [appBundleURL], zipFilePath: appURL, password: nil, progress: nil)
                            finish(.success(()))
                        } catch {
                            finish(.failure(.fileOperationFailed(error)))
                        }
                    } else {
                        finish(.success(()))
                    }
                }
            } catch {
                finish(.failure(.unknown(error.localizedDescription)))
            }
        }
        
        return progress
    }
}

// MARK: - Helper Functions

func saveProvisioningProfile(_ profile: ProvisioningProfile) throws -> String {
    let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("\(profile.uuid).mobileprovision")
    try profile.data.write(to: tempURL)
    return tempURL.path
}
extension Data {
    var bytes: [UInt8] {
        return [UInt8](self)
    }
}

extension Optional where Wrapped == Data {
    var bytes: [UInt8] {
        return self?.bytes ?? []
    }
}

extension URL {
    @available(iOS, deprecated: 16.0, message: "Use URL.temporaryDirectory on iOS 16 and above")
    static var temporaryDirectory: URL {
        let documentDirectory = FileManager.default.temporaryDirectory
        return documentDirectory
    }
}
