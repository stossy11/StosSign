//
//  Capability.swift
//  StosSign
//
//  Created by Stossy11 on 14/2/2026.
//

public struct Capability: Codable {
    var id: String
    var attributes: [CapabilityAttributes]
}

public struct CapabilityAttributes: Codable {
    var entitlements: [CapabilityEntitlement]?
    var supportsWildcard: Int
    var validTeamTypes: [String]
}

public struct CapabilityEntitlement: Codable {
    var key: String
    var profileKey: String
}
