//
//  Application.swift
//  StosSign
//
//  Created by Stossy11 on 19/03/2025.
//

import Foundation
import ZSign
#if os(iOS)
import UIKit
#endif


public typealias Entitlement = String

public class Application: NSObject {
    // MARK: - Public Properties
    
    public let name: String
    public let bundleIdentifier: String
    public let version: String
    public let buildVersion: String
    public let minimumiOSVersion: OperatingSystemVersion
    public let supportedDeviceTypes: DeviceType
    public let fileURL: URL
    public let bundle: Bundle
    
    /// Whether the application has private entitlements
    public var hasPrivateEntitlements: Bool = false
    
    // MARK: - Lazy Properties
    
    /// Dictionary of application entitlements
    public var entitlements: [Entitlement: Any] {
        if let cached = _entitlements {
            return cached
        }
        
        guard let entitlementsString = try? self.entitlementsString, !entitlementsString.isEmpty,
              let data = entitlementsString.data(using: .utf8) else {
            _entitlements = [:]
            return [:]
        }
        
        do {
            guard let entitlements = try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            ) as? [Entitlement: Any] else {
                _entitlements = [:]
                return [:]
            }
            
            _entitlements = entitlements
            return entitlements
        } catch {
            print("Error parsing entitlements: \(error)")
            _entitlements = [:]
            return [:]
        }
    }
    
    /// Raw entitlements string
    public var entitlementsString: String {
        get throws {
            if let cached = _entitlementsString {
                return cached
            }
            
            let path = fileURL.path + "/"
            
            do {
                let rawEntitlements = try EntitlementsParser.extractEntitlements(from: path)
                _entitlementsString = rawEntitlements
                return rawEntitlements
            } catch {
                throw EntitlementError.failedToExtract(error)
            }
        }
    }
    
    /// Associated provisioning profile
    public var provisioningProfile: ProvisioningProfile? {
        if let cached = _provisioningProfile {
            return cached
        }
        
        let provisioningProfileURL = fileURL.appendingPathComponent("embedded.mobileprovision")
        let decoder = PropertyListDecoder()

        do {
            let data = try Data(contentsOf: provisioningProfileURL)
            let profile = try decoder.decode(ProvisioningProfile.self, from: data)
            _provisioningProfile = profile
            return profile
        } catch {
            print("Failed to decode provisioning profile: \(error)")
            return nil
        }
    }
    
    /// App extensions contained in this application
    public var appExtensions: Set<Application> {
        guard let plugInsURL = bundle.builtInPlugInsURL else {
            return []
        }
        
        return Set(
            FileManager.default
                .enumerateContents(at: plugInsURL, options: [.skipsSubdirectoryDescendants])
                .compactMap { url -> Application? in
                    guard url.pathExtension.lowercased() == "appex",
                          let appExtension = Application(fileURL: url) else {
                        return nil
                    }
                    return appExtension
                }
        )
    }

    
    #if os(iOS)
    /// The application icon, if available
    public var icon: UIImage? {
        guard let iconName = self.iconName else {
            return nil
        }
        
        return UIImage(named: iconName, in: self.bundle, compatibleWith: nil)
    }
    #endif
    
    // MARK: - Private Properties
    
    private let iconName: String?
    private var _entitlements: [Entitlement: Any]?
    private var _entitlementsString: String?
    private var _provisioningProfile: ProvisioningProfile?
    
    // MARK: - Initializers
    
    public init?(fileURL: URL) {
        guard let bundle = Bundle(url: fileURL) else {
            return nil
        }
        
        let infoPlistURL = bundle.bundleURL.appendingPathComponent("Info.plist")
        guard let infoDictionary = NSDictionary(contentsOf: infoPlistURL) as? [String: Any] else {
            return nil
        }
        
        // Extract required information
        guard let name = infoDictionary["CFBundleDisplayName"] as? String ?? infoDictionary[kCFBundleNameKey as String] as? String,
              let bundleIdentifier = infoDictionary[kCFBundleIdentifierKey as String] as? String else {
            return nil
        }
        
        let version = infoDictionary["CFBundleShortVersionString"] as? String ?? "1.0"
        let buildVersion = infoDictionary[kCFBundleVersionKey as String] as? String ?? "1"
        
        let minimumVersion = Self.parseMinimumOSVersion(from: infoDictionary["MinimumOSVersion"] as? String ?? "1.0")
        
        let supportedDeviceTypes = Self.parseSupportedDeviceTypes(from: infoDictionary)
        
        let iconName = Self.findIconName(in: infoDictionary)
        
        self.bundle = bundle
        self.fileURL = fileURL
        self.name = name
        self.bundleIdentifier = bundleIdentifier
        self.version = version
        self.buildVersion = buildVersion
        self.minimumiOSVersion = minimumVersion
        self.supportedDeviceTypes = supportedDeviceTypes
        self.iconName = iconName
        
        super.init()
    }
    
    // MARK: - Private Methods
    
    private static func parseMinimumOSVersion(from versionString: String) -> OperatingSystemVersion {
        let components = versionString.components(separatedBy: ".")
        
        let major = components.indices.contains(0) ? Int(components[0]) ?? 0 : 0
        let minor = components.indices.contains(1) ? Int(components[1]) ?? 0 : 0
        let patch = components.indices.contains(2) ? Int(components[2]) ?? 0 : 0
        
        return OperatingSystemVersion(
            majorVersion: major,
            minorVersion: minor,
            patchVersion: patch
        )
    }
    
    private static func parseSupportedDeviceTypes(from infoDictionary: [String: Any]) -> DeviceType {
        if let deviceFamilies = infoDictionary["UIDeviceFamily"] {
            if let rawDeviceFamily = deviceFamilies as? Int {
                return DeviceType.from(uiDeviceFamily: rawDeviceFamily)
            } else if let deviceFamiliesArray = deviceFamilies as? [Int], !deviceFamiliesArray.isEmpty {
                return deviceFamiliesArray.reduce(DeviceType.none) { result, family in
                    DeviceType.combine(result, DeviceType.from(uiDeviceFamily: family))
                }
            }
        }
        
        return .iPhone
    }

    private static func findIconName(in infoDictionary: [String: Any]) -> String? {
        if let icons = infoDictionary["CFBundleIcons"] as? [String: Any],
           let primaryIcon = icons["CFBundlePrimaryIcon"] {
            if let iconString = primaryIcon as? String {
                return iconString
            } else if let primaryIconDict = primaryIcon as? [String: Any],
                      let iconFiles = primaryIconDict["CFBundleIconFiles"] as? [String],
                      let lastIcon = iconFiles.last {
                return lastIcon
            }
        }
        
        if let iconFiles = infoDictionary["CFBundleIconFiles"] as? [String],
           let lastIcon = iconFiles.last {
            return lastIcon
        }
        
        return infoDictionary["CFBundleIconFile"] as? String
    }
    
    public enum EntitlementError: Error, LocalizedError {
        case failedToExtract(Error)
        
        public var errorDescription: String? {
            switch self {
            case .failedToExtract(let error):
                return "Failed to extract entitlements: \(error.localizedDescription)"
            }
        }
    }
}

// MARK: - Extensions
extension FileManager {
    func enumerateContents(at url: URL, options: DirectoryEnumerationOptions = []) -> [URL] {
        guard let enumerator = self.enumerator(
            at: url,
            includingPropertiesForKeys: nil,
            options: options,
            errorHandler: nil
        ) else {
            return []
        }
        
        return enumerator.compactMap { $0 as? URL }
    }
}
