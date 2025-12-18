//
//  Authentication.swift
//  StosSign
//
//  Created by Stossy11 on 18/12/2025.
//

import Foundation
import StosSign_API

public typealias AnisetteData = StosSign_API.AnisetteData
public typealias Account = StosSign_API.Account
public typealias AppleAPISession = StosSign_API.AppleAPISession
public typealias AppleAPIError = StosSign_API.AppleAPIError


public final class Authentication {
    public func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        verificationHandler: ((@escaping (String?) -> Void) async -> Void)? = nil
    ) async throws -> (Account, AppleAPISession) {
        try await AppleAPI.shared.authenticate(appleID: unsanitizedAppleID, password: password, anisetteData: anisetteData, verificationHandler: verificationHandler)
    }
}
