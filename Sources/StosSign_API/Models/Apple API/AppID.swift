//
//  AppID.swift
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//

import Foundation

public struct AppID { // I wanted to use a Codable struct but for some reason no matter how much i tried it wouldn't work due to the features and enabled Features stuff
    public var name: String
    public var identifier: String
    public var bundleIdentifier: String
    public var expirationDate: Date?
    public var features: [String: Any]
    public var entitlements: [String]

    public init(name: String, identifier: String, bundleIdentifier: String, expirationDate: Date?, features: [String: Any]) {
        self.name = name
        self.identifier = identifier
        self.bundleIdentifier = bundleIdentifier
        self.expirationDate = expirationDate
        self.features = features
        self.entitlements = []
    }

    public init?(responseDictionary: [String: Any]) {
        guard let name = responseDictionary["name"] as? String,
              let identifier = responseDictionary["appIdId"] as? String,
              let bundleIdentifier = responseDictionary["identifier"] as? String else {
            return nil
        }

        let allFeatures = responseDictionary["features"] as? [String: Any] ?? [:]
        let enabledFeatures = responseDictionary["enabledFeatures"] as? [String] ?? []

        var features = [String: Any]()
        for feature in enabledFeatures {
            if let value = allFeatures[String(describing: feature)] {
                features[feature] = value
            }
        }

        let expirationDate = responseDictionary["expirationDate"] as? Date
        self.init(name: name, identifier: identifier, bundleIdentifier: bundleIdentifier, expirationDate: expirationDate, features: features)
    }
}
