//
//  SignerType.swift
//  StosSign
//
//  Created by Stossy11 on 4/9/2026.
//

import Foundation

public enum SignerType: String, Codable, CaseIterable, Identifiable {
    public var id: String { rawValue }
    
    case security_framework
    case codesignkit
    // these two may come eventually, but for now we don't need it.
    // case ldid
    // case custom
    
    public var displayName: String {
        switch self {
        case .security_framework:
            return "Security.framework"
        case .codesignkit:
            return "CodeSignKit"
        }
    }
}
