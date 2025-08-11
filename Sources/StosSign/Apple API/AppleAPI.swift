//
//  AppleAPI.swift
//  StosSign
//
//  Created by Stossy11 on 18/03/2025.
//

import Foundation

let clientID = "XABBG36SBA"
let QH_Protocol = "QH65B2"
let V1_Protocol = "v1"
let authProtocol = "A1234"

public class AppleAPI {
    let session = URLSession(configuration: URLSessionConfiguration.ephemeral)
    let dateFormatter = ISO8601DateFormatter()
    let qhURL = URL(string: "https://developerservices2.apple.com/services/\(QH_Protocol)/")!
    let v1URL = URL(string: "https://developerservices2.apple.com/services/\(V1_Protocol)/")!
    
    public init() {}
    
    public func fetchTeamsForAccount(account: Account, session: AppleAPISession, completion: @escaping ([Team]?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("listTeams.action")
        
        sendRequestWithURL(requestURL: url, additionalParameters: nil, session: session, team: nil) { response, error in
            guard let response else {
                completion(nil, error)
                return
            }
            
            var APIerror: AppleAPIError? = nil
            guard let array = response["teams"] as? [[String: Any]] else {
                if error == nil {
                    if let result = response["resultCode"] {
                        let resultCode = (result as? NSNumber)?.intValue ?? 0
                        
                        if resultCode == 0 {
                            APIerror = .unknown
                        } else {
                            let errorDescription = response["userString"] as? String ?? response["resultString"] as? String
                            let localizedDescription = String(format: "%@ (%@)", errorDescription ?? "", "\(resultCode)")
                            
                            APIerror = .customError(code: resultCode, message: localizedDescription)
                        }
                    } else {
                        APIerror = .badServerResponse
                    }
                }
                
                completion(nil, APIerror ?? error)
                return
            }
            
            var teams: [Team] = []
            for dictionary in array {
                if let team = Team(account: account, responseDictionary: dictionary) {
                    teams.append(team)
                }
            }
            
            (teams.count == 0) ? completion(nil, AppleAPIError.noTeams) : completion(teams, nil)
        }
    }
    
    
    public func fetchDevicesForTeam(team: Team, session: AppleAPISession, types: DeviceType, completion: @escaping ([Device]?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios").appendingPathComponent("listDevices.action")
        
        self.sendRequestWithURL(requestURL: url, additionalParameters: nil, session: session, team: team) { response, error in
            guard let response else {
                completion(nil, error)
                return
            }
            
            let responseError = error
            var APIerror: AppleAPIError? = nil
            do {
                let data = try JSONSerialization.data(withJSONObject: response["devices"] ?? [])
                let devices = try JSONDecoder().decode([Device].self, from: data)
                var devicesChecked = devices
                devicesChecked.removeAll(where: { types != $0.type })
                completion(devicesChecked, nil)
            } catch {
                if responseError == nil {
                    if let result = response["resultCode"] {
                        let resultCode = (result as? NSNumber)?.intValue ?? 0
                        
                        if resultCode == 0 {
                            APIerror = .unknown
                        } else {
                            let errorDescription = response["userString"] as? String ?? response["resultString"] as? String
                            let localizedDescription = String(format: "%@ (%@)", errorDescription ?? "", "\(resultCode)")
                            
                            APIerror = .customError(code: resultCode, message: localizedDescription)
                        }
                    } else {
                        APIerror = .badServerResponse
                    }
                }
                
                completion(nil, APIerror ?? error)
            }
        }
    }
    
    public func registerDeviceWithName(name: String, identifier: String, type: DeviceType, team: Team, session: AppleAPISession, completion: @escaping (Device?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios").appendingPathComponent("addDevice.action")
        
        var parameters = [
            "deviceNumber": identifier,
            "name": name
        ]
        
        switch type {
        case .iPad:
            parameters["DTDK_Platform"] = "ios"
        case .AppleTV:
            parameters["DTDK_Platform"] = "tvos"
            parameters["subPlatform"] = "tvOS"
        default: break
        }
        
        sendRequestWithURL(requestURL: url, additionalParameters: parameters, session: session, team: team) { response, error in
            guard let response else {
                completion(nil, error ?? AppleAPIError.unknown)
                return
            }
            
            var APIerror: AppleAPIError? = nil
            
            guard let deviceDictionary = response["device"] as? [String: Any] else {
                if error == nil {
                    if let result = response["resultCode"] as? Int {
                        
                        if result == 0 {
                            APIerror = .unknown
                        } else if result == 35 {
                            APIerror = .deviceAlreadyRegistered
                        } else {
                            let errorDescription = response["userString"] as? String ?? response["resultString"] as? String
                            let localizedDescription = String(format: "%@ (%@)", errorDescription ?? "", "\(result)")
                            
                            APIerror = .customError(code: result, message: localizedDescription)
                        }
                    } else {
                        APIerror = .badServerResponse
                    }
                }
                
                completion(nil, APIerror ?? error ?? AppleAPIError.unknown)
                return
            }
            
            
            do {
                let jsonData = try JSONSerialization.data(withJSONObject: deviceDictionary, options: [])
                let device = try JSONDecoder().decode(Device.self, from: jsonData)
                completion(device, nil)
                return
            } catch {
                if let result = response["resultCode"] {
                    let resultCode = (result as? NSNumber)?.intValue ?? 0
                    
                    if resultCode == 0 {
                        completion(nil, error)
                        return
                    } else {
                        let errorDescription = response["userString"] as? String ?? response["resultString"] as? String
                        let localizedDescription = String(format: "%@ (%@)", errorDescription ?? "", "\(resultCode)")
                        
                        APIerror = .customError(code: resultCode, message: localizedDescription)
                    }
                } else {
                    APIerror = .badServerResponse
                }
                
                completion(nil, APIerror ?? AppleAPIError.unknown)
                return
            }
        }
    }
    
    public func fetchCertificatesForTeam(team: Team, session: AppleAPISession, completion: @escaping ([Certificate]?, Error?) -> Void) {
        let url = v1URL.appendingPathComponent("certificates")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        sendServicesRequest(originalRequest: request, additionalParameters: ["filter[certificateType]": "IOS_DEVELOPMENT"], session: session, team: team) { (responseDictionary, error) in
            guard let data = responseDictionary?["data"] as? [[String: Any]] else {
                print("Failed to parse certificates response: \(String(describing: responseDictionary))")
                completion(nil, error)
                return
            }

            print("Certificates Response: \(data)")
            
            let decoder = JSONDecoder()
            let certificates = data.compactMap { dict -> Certificate? in
                return Certificate(responseDictionary: dict)
            }
            
            completion(certificates, nil)
        }
    }

    func convertDatesToStrings(in dict: [String: Any]) -> [String: Any] {
        var newDict = [String: Any]()
        for (key, value) in dict {
            if let date = value as? Date {
                let formatter = ISO8601DateFormatter()
                newDict[key] = formatter.string(from: date)
            } else if let subDict = value as? [String: Any] {
                newDict[key] = convertDatesToStrings(in: subDict)
            } else if let array = value as? [Any] {
                newDict[key] = array.map { element -> Any in
                    if let elementDict = element as? [String: Any] {
                        return convertDatesToStrings(in: elementDict)
                    } else if let date = element as? Date {
                        let formatter = ISO8601DateFormatter()
                        return formatter.string(from: date)
                    }
                    return element
                }
            } else {
                newDict[key] = value
            }
        }
        return newDict
    }
    
    public func addCertificateWithMachineName(machineName: String, team: Team, session: AppleAPISession, completion: @escaping (Certificate?, Error?) -> Void) {
        guard let certificateRequest = CertificateRequest.generate(), let csr = certificateRequest.csr, let csrString = String(data: csr, encoding: .utf8) else {
            print("Failed to generate CSR")
            completion(nil, AppleAPIError.invalidCertificateRequest)
            return
        }


        print("PKey: \(String(data: certificateRequest.privateKey ?? Data(), encoding: .utf8) ?? "nil")")

        let url = qhURL.appendingPathComponent("ios/submitDevelopmentCSR.action")
        
        sendRequestWithURL(requestURL: url,
                           additionalParameters: [
                            "csrContent": csrString,
                            "machineId": UUID().uuidString,
                            "machineName": machineName
                           ], session: session, team: team) { (responseDictionary, error) in
                               guard let certRequestDict = responseDictionary?["certRequest"] as? [String: Any] else {
                                   print("Failed to parse certificate request response: \(String(describing: responseDictionary))")

                                    if let resultCode = responseDictionary?["resultCode"] as? Int {
                                       switch resultCode {
                                       case 7460:
                                           completion(nil, AppleAPIError.customError(code: 7460, message: "You already have a current iOS Development certificate or a pending certificate request."))
                                       default:
                                           completion(nil, error ?? AppleAPIError.badServerResponse)
                                       }

                                       return
                                    }

                                   completion(nil, error)
                                   return
                               }

                               print("Certificate Request Response: \(certRequestDict)")
                               
                               let certificate = Certificate(responseDictionary: certRequestDict)!
                               
                               certificate.privateKey = certificateRequest.privateKey
                               completion(certificate, nil)
                           }
    }
    
    public func revokeCertificate(certificate: Certificate, team: Team, session: AppleAPISession, completion: @escaping (Bool, Error?) -> Void) {
        let url = v1URL.appendingPathComponent("certificates").appendingPathComponent(certificate.identifier ?? "")
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        
        sendServicesRequest(originalRequest: request, additionalParameters: nil, session: session, team: team) { (responseDictionary, error) in
            completion(responseDictionary != nil, error)
        }
    }
    
    public func fetchAppIDsForTeam(team: Team, session: AppleAPISession, completionHandler: @escaping ([AppID]?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/listAppIds.action")
        
        sendRequestWithURL(requestURL: url, additionalParameters: nil, session: session, team: team) { response, error in
            guard let response else {
                completionHandler(nil, error)
                return
            }
            
            guard let array = response["appIds"] as? [[String: Any]] else {
                completionHandler(nil, error ?? AppleAPIError.badServerResponse)
                return
            }
            
            let appIDs = array.compactMap { AppID(responseDictionary: $0) }
            
            completionHandler(appIDs.isEmpty ? nil : appIDs, nil)
        }
    }
    
    public func addAppID(name: String, bundleIdentifier: String, team: Team, session: AppleAPISession, completionHandler: @escaping (AppID?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/addAppId.action")
        
        // Sanitize name similar to ObjC implementation
        var sanitizedName = name.folding(options: .diacriticInsensitive, locale: nil)
        sanitizedName = sanitizedName.components(separatedBy: CharacterSet.alphanumerics.union(.whitespaces).inverted).joined()
        
        if sanitizedName.isEmpty {
            sanitizedName = "App"
        }
        
        let parameters = [
            "identifier": bundleIdentifier,
            "name": sanitizedName
        ]
        
        sendRequestWithURL(requestURL: url, additionalParameters: parameters, session: session, team: team) { response, error in
            guard let response else {
                print("Error fetching App ID: \(error?.localizedDescription ?? "Unknown error")")
                completionHandler(nil, error)
                return
            }
            
            guard let dictionary = response["appId"] as? [String: Any] else {
                // Handle result code errors
                if let resultCode = response["resultCode"] as? Int {
                    switch resultCode {
                    case 35:
                        let error = AppleAPIError.customError(
                            code: resultCode,
                            message: "Invalid App ID Name (\(sanitizedName))"
                        )
                        completionHandler(nil, error)
                    case 9120:
                        completionHandler(nil, AppleAPIError.maximumAppIDLimitReached)
                    case 9401:
                        completionHandler(nil, AppleAPIError.bundleIdentifierUnavailable)
                    case 9412:
                        completionHandler(nil, AppleAPIError.invalidBundleIdentifier)
                    case 9400:
                        completionHandler(nil, AppleAPIError.bundleIdentifierUnavailable)
                    default:
                        completionHandler(nil, error)
                    }
                    return
                }
                
                completionHandler(nil, error ?? AppleAPIError.badServerResponse)
                return
            }
            
            
            guard let appID = AppID(responseDictionary: dictionary) else {
                completionHandler(nil, AppleAPIError.badServerResponse)
                return
            }
            
            completionHandler(appID, nil)
        }
    }
    
    public func updateAppID(_ appID: AppID, team: Team, session: AppleAPISession, completionHandler: @escaping (AppID?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/updateAppId.action")
        
        var parameters: [String: Any] = ["appIdId": appID.identifier]
        
        // Add features
        appID.features.forEach { key, value in
            parameters[key] = value
        }
        
        // Handle entitlements based on team type
        var entitlements = appID.entitlements
        
        if team.type == .free {
            entitlements = entitlements.filter { key in
                freeDeveloperCanUseEntitlement(key)
            }
        }
        
        parameters["entitlements"] = entitlements
        
        sendRequestWithURL(requestURL: url, additionalParameters: parameters.mapValues { String(describing: $0) }, session: session, team: team) { response, error in
            guard let response else {
                completionHandler(nil, error)
                return
            }
            
            guard let dictionary = response["appId"] as? [String: Any] else {
                // Handle result code errors
                if let resultCode = response["resultCode"] as? Int {
                    switch resultCode {
                    case 35:
                        completionHandler(nil, AppleAPIError.invalidAppIDName)
                    case 9100:
                        completionHandler(nil, AppleAPIError.appIDDoesNotExist)
                    case 9412:
                        completionHandler(nil, AppleAPIError.invalidBundleIdentifier)
                    default:
                        completionHandler(nil, error)
                    }
                    return
                }
                
                completionHandler(nil, error ?? AppleAPIError.badServerResponse)
                return
            }
            
            guard let updatedAppID = AppID(responseDictionary: dictionary) else {
                completionHandler(nil, AppleAPIError.badServerResponse)
                return
            }
            
            completionHandler(updatedAppID, nil)
        }
    }
    
    public func deleteAppID(_ appID: AppID, team: Team, session: AppleAPISession, completionHandler: @escaping (Bool, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/deleteAppId.action")
        
        let parameters = ["appIdId": appID.identifier]
        
        sendRequestWithURL(requestURL: url, additionalParameters: parameters, session: session, team: team) { response, error in
            guard let response else {
                completionHandler(false, error)
                return
            }
            
            // Check result code
            if let resultCode = response["resultCode"] as? Int {
                switch resultCode {
                case 9100:
                    completionHandler(false, AppleAPIError.appIDDoesNotExist)
                case 0:
                    completionHandler(true, nil)
                default:
                    completionHandler(false, error)
                }
                return
            }
            
            completionHandler(false, error ?? AppleAPIError.badServerResponse)
        }
    }
    
    // MARK: - App Groups
    
    public func fetchAppGroupsForTeam(team: Team, session: AppleAPISession, completionHandler: @escaping ([AppGroup]?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/listApplicationGroups.action")
        
        sendRequestWithURL(requestURL: url, additionalParameters: nil, session: session, team: team) { response, error in
            guard let response else {
                completionHandler(nil, error)
                return
            }
            
            guard let data = try? JSONSerialization.data(withJSONObject: response["applicationGroupList"] ?? []) else {
                completionHandler(nil, error ?? AppleAPIError.badServerResponse)
                return
            }
            
            do {
                let groups = try JSONDecoder().decode([AppGroup].self, from: data)
                completionHandler(groups.isEmpty ? nil : groups, nil)
            } catch {
                completionHandler(nil, error)
            }
        }
    }
    
    public func addAppGroup(name: String, groupIdentifier: String, team: Team, session: AppleAPISession, completionHandler: @escaping (AppGroup?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/addApplicationGroup.action")
        
        let parameters = [
            "identifier": groupIdentifier,
            "name": name
        ]
        
        sendRequestWithURL(requestURL: url, additionalParameters: parameters, session: session, team: team) { response, error in
            guard let response else {
                completionHandler(nil, error)
                return
            }
            
            guard let dictionary = response["applicationGroup"] as? [String: Any] else {
                if let resultCode = response["resultCode"] as? Int, resultCode == 35 {
                    completionHandler(nil, AppleAPIError.invalidAppGroup)
                    return
                }
                
                completionHandler(nil, error ?? AppleAPIError.badServerResponse)
                return
            }
            
            guard let data = try? JSONSerialization.data(withJSONObject: dictionary) else {
                completionHandler(nil, error ?? AppleAPIError.badServerResponse)
                return
            }
            
            
            
            do {
                let groups = try JSONDecoder().decode(AppGroup.self, from: data)
                completionHandler(groups, nil)
            } catch {
                completionHandler(nil, error)
            }
        }
    }
    
    public func assignAppID(_ appID: AppID, toGroups groups: [AppGroup], team: Team, session: AppleAPISession, completionHandler: @escaping (Bool, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/assignApplicationGroupToAppId.action")
        
        let groupIDs = groups.map { $0.identifier }
        
        let parameters: [String: Any] = [
            "appIdId": appID.identifier,
            "applicationGroups": groupIDs
        ]
        
        sendRequestWithURL(requestURL: url, additionalParameters: parameters.mapValues { ($0 as? [String])?.joined(separator: ",") ?? "" }, session: session, team: team) { response, error in
            guard let response else {
                completionHandler(false, error)
                return
            }
            
            if let resultCode = response["resultCode"] as? Int {
                switch resultCode {
                case 9115:
                    completionHandler(false, AppleAPIError.appIDDoesNotExist)
                case 35:
                    completionHandler(false, AppleAPIError.appGroupDoesNotExist)
                case 0:
                    completionHandler(true, nil)
                default:
                    completionHandler(false, error)
                }
                return
            }
            
            completionHandler(false, error ?? AppleAPIError.badServerResponse)
        }
    }
    
    public func fetchProvisioningProfileForAppID(appID: AppID, deviceType: DeviceType, team: Team, session: AppleAPISession, completionHandler: @escaping (ProvisioningProfile?, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/downloadTeamProvisioningProfile.action")
        
        var parameters: [String: String] = ["appIdId": appID.identifier]
        
        switch deviceType {
        case .iPhone, .iPad:
            parameters["DTDK_Platform"] = "ios"
        case .AppleTV:
            parameters["DTDK_Platform"] = "tvos"
            parameters["subPlatform"] = "tvOS"
        default:
            break
        }
        
        sendRequestWithURL(requestURL: url, additionalParameters: parameters, session: session, team: team) { response, error in
            guard let response else {
                completionHandler(nil, error)
                return
            }
            
            if let resultCode = response["resultCode"] as? Int, resultCode == 8201 {
                completionHandler(nil, AppleAPIError.appIDDoesNotExist)
                return
            }
            
            guard let dictionary = response["provisioningProfile"] else {
                completionHandler(nil, error ?? AppleAPIError.badServerResponse)
                return
            }
            
            do {
                print("Provisioning Profile Response: \(dictionary)")
                let provisioningProfile = ProvisioningProfile(dictionary as! [String: Any])
                completionHandler(provisioningProfile, nil)
            } catch {
                completionHandler(nil, error)
            }
        }
    }
    
    
    public func deleteProvisioningProfile(_ provisioningProfile: ProvisioningProfile, team: Team, session: AppleAPISession, completionHandler: @escaping (Bool, Error?) -> Void) {
        let url = qhURL.appendingPathComponent("ios/deleteProvisioningProfile.action")
        
        let parameters = [
            "provisioningProfileId": provisioningProfile.identifier,
            "teamId": team.identifier
        ]
        
        sendRequestWithURL(requestURL: url, additionalParameters: parameters, session: session, team: team) { response, error in
            guard let response else {
                completionHandler(false, error)
                return
            }
            
            if let resultCode = response["resultCode"] as? Int {
                switch resultCode {
                case 35:
                    completionHandler(false, AppleAPIError.invalidProvisioningProfileIdentifier)
                case 8101:
                    completionHandler(false, AppleAPIError.provisioningProfileDoesNotExist)
                case 0:
                    completionHandler(true, nil)
                default:
                    completionHandler(false, error)
                }
                return
            }
            
            completionHandler(false, error ?? AppleAPIError.badServerResponse)
        }
    }
    
    
    public func sendServicesRequest(originalRequest: URLRequest, additionalParameters: [String: String]? = nil, session: AppleAPISession,team: Team, completion: @escaping ([String: Any]?, Error?) -> Void) {
        var request = originalRequest
        
        var queryItems = [URLQueryItem(name: "teamId", value: team.identifier)]
        
        additionalParameters?.forEach { key, value in
            queryItems.append(URLQueryItem(name: key, value: value))
        }
        
        var components = URLComponents()
        components.queryItems = queryItems
        let queryString = components.query ?? ""
        
        do {
            let bodyData = try JSONSerialization.data(
                withJSONObject: ["urlEncodedQueryParams": queryString],
                options: []
            )
            request.httpBody = bodyData
        } catch {
            let nsError = NSError(
                domain: "AppleAPIErrorDomain",
                code: -1,
                userInfo: [NSUnderlyingErrorKey: error]
            )
            completion(nil, nsError)
            return
        }
        
        let originalHTTPMethod = request.httpMethod
        request.httpMethod = "POST"
        
        let httpHeaders: [String: String] = [
            "Content-Type": "application/vnd.api+json",
            "User-Agent": "Xcode",
            "Accept": "application/vnd.api+json",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-HTTP-Method-Override": originalHTTPMethod ?? "",
            "X-Apple-I-Identity-Id": session.dsid,
            "X-Apple-GS-Token": session.authToken,
            "X-Apple-I-MD-M": session.anisetteData.machineID,
            "X-Apple-I-MD": session.anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": session.anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": String(session.anisetteData.routingInfo),
            "X-Mme-Device-Id": session.anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": session.anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": dateFormatter.string(from: session.anisetteData.date),
            "X-Apple-Locale": session.anisetteData.locale.identifier,
            "X-Apple-I-TimeZone": session.anisetteData.timeZone.abbreviation() ?? ""
        ]
        
        httpHeaders.forEach { key, value in
            request.setValue(value, forHTTPHeaderField: key)
        }
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data else {
                completion(nil, error)
                return
            }
            
            guard !data.isEmpty else {
                completion([:], nil)
                return
            }
            
            do {
                let responseDictionary = try JSONSerialization.jsonObject(
                    with: data,
                    options: []
                ) as? [String: Any]
                
                completion(responseDictionary, nil)
            } catch {
                completion(nil, AppleAPIError.badServerResponse)
            }
        }
        
        task.resume()
    }
    
    
    public func sendRequestWithURL(requestURL: URL, additionalParameters: [String: String]?, session: AppleAPISession, team: Team?, completion: @escaping ([String: Any]?, Error?) -> Void) {
        var parameters: [String: String] = [
            "clientId": clientID,
            "protocolVersion": QH_Protocol, // v1 Protocol is newer
            "requestId": UUID().uuidString.uppercased()
        ]
        
        if let team = team {
            parameters["teamId"] = team.identifier
        }
        
        additionalParameters?.forEach { key, value in
            parameters[key] = value
        }
        
        do {
            let bodyData = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)
            
            var urlString = requestURL.absoluteString
            urlString.append("?clientId=\(clientID)")
            guard let url = URL(string: urlString) else {
                let error = AppleAPIError.invalidParameters
                completion(nil, error)
                return
            }
            
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = bodyData
            
            let httpHeaders: [String: String] = [
                "Content-Type": "text/x-xml-plist",
                "User-Agent": "Xcode",
                "Accept": "text/x-xml-plist",
                "Accept-Language": "en-us",
                "X-Apple-App-Info": "com.apple.gs.xcode.auth",
                "X-Xcode-Version": "11.2 (11B41)",
                "X-Apple-I-Identity-Id": session.dsid,
                "X-Apple-GS-Token": session.authToken,
                "X-Apple-I-MD-M": session.anisetteData.machineID,
                "X-Apple-I-MD": session.anisetteData.oneTimePassword,
                "X-Apple-I-MD-LU": session.anisetteData.localUserID,
                "X-Apple-I-MD-RINFO": "\(session.anisetteData.routingInfo)",
                "X-Mme-Device-Id": session.anisetteData.deviceUniqueIdentifier,
                "X-MMe-Client-Info": session.anisetteData.deviceDescription,
                "X-Apple-I-Client-Time": dateFormatter.string(from: session.anisetteData.date),
                "X-Apple-Locale": session.anisetteData.locale.identifier,
                "X-Apple-I-Locale": session.anisetteData.locale.identifier,
                "X-Apple-I-TimeZone": session.anisetteData.timeZone.abbreviation() ?? "GMT"
            ]
            
            for (key, value) in httpHeaders {
                request.setValue(value, forHTTPHeaderField: key)
            }
            
            self.session.dataTask(with: request) { data, response, error in
                guard let data = data else {
                    completion(nil, error)
                    return
                }
                
                do {
                    if let responseDictionary = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
                        completion(responseDictionary, nil)
                    } else {
                        let error = NSError(domain: NSURLErrorDomain, code: NSURLErrorBadServerResponse, userInfo: [NSUnderlyingErrorKey: error ?? AppleAPIError.badServerResponse ])
                        completion(nil, error)
                    }
                } catch let parseError {
                    let error = NSError(domain: NSURLErrorDomain, code: NSURLErrorBadServerResponse, userInfo: [NSUnderlyingErrorKey: parseError])
                    completion(nil, error)
                }
            }.resume()
        } catch let serializationError {
            let error = AppleAPIError.invalidParameters
            completion(nil, error)
        }
    }
    
    public func authenticate(
        appleID unsanitizedAppleID: String,
        password: String,
        anisetteData: AnisetteData,
        verificationHandler: ((@escaping (String?) -> Void) -> Void)? = nil,
        completionHandler: @escaping (Account?, AppleAPISession?, Error?) -> Void
    ) {
        let sanitizedAppleID = unsanitizedAppleID.lowercased()
        
        struct AuthenticationStage {
            let dsid: String?
            let idmsToken: String?
            let sessionKey: Data?
            let clientContext: [String: Any]
        }
        
        do {
            let clientDictionary: [String: Any] = [
                "bootstrap": true,
                "icscrec": true,
                "pbe": false,
                "prkgen": true,
                "svct": "iCloud",
                "loc": Locale.current.identifier,
                "X-Apple-Locale": Locale.current.identifier,
                "X-Apple-I-MD": anisetteData.oneTimePassword,
                "X-Apple-I-MD-M": anisetteData.machineID,
                "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
                "X-Apple-I-MD-LU": anisetteData.localUserID,
                "X-Apple-I-MD-RINFO": anisetteData.routingInfo,
                "X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber,
                "X-Apple-I-Client-Time": dateFormatter.string(from: anisetteData.date),
                "X-Apple-I-TimeZone": TimeZone.current.abbreviation() ?? "PST"
            ]
            
            let context = GSAContext(username: sanitizedAppleID, password: password)
            guard let publicKey = context.start() else {
                throw AppleAPIError.authenticationHandshakeFailed
            }
            
            let initialParameters: [String: Any] = [
                "A2k": publicKey,
                "cpd": clientDictionary,
                "ps": ["s2k", "s2k_fo"],
                "o": "init",
                "u": sanitizedAppleID
            ]
            
            sendAuthenticationRequest(parameters: initialParameters, anisetteData: anisetteData) { result in
                do {
                    let responseDictionary = try result.get()
                    
                    guard let c = responseDictionary["c"] as? String,
                          let salt = responseDictionary["s"] as? Data,
                          let iterations = responseDictionary["i"] as? Int,
                          let serverPublicKey = responseDictionary["B"] as? Data
                    else {
                        throw URLError(.badServerResponse)
                    }
                    
                    context.salt = salt
                    context.serverPublicKey = serverPublicKey
                    
                    let sp = responseDictionary["sp"] as? String
                    let isHexadecimal = (sp == "s2k_fo")
                    
                    guard let verificationMessage = context.makeVerificationMessage(
                        iterations: iterations,
                        isHexadecimal: isHexadecimal
                    ) else {
                        throw AppleAPIError.authenticationHandshakeFailed
                    }
                    
                    let verificationParameters: [String: Any] = [
                        "c": c,
                        "cpd": clientDictionary,
                        "M1": verificationMessage,
                        "o": "complete",
                        "u": sanitizedAppleID
                    ]
                    
                    self.sendAuthenticationRequest(
                        parameters: verificationParameters,
                        anisetteData: anisetteData
                    ) { result in
                        do {
                            let responseDictionary = try result.get()
                            
                            guard let serverVerificationMessage = responseDictionary["M2"] as? Data,
                                  let serverDictionary = responseDictionary["spd"] as? Data,
                                  let statusDictionary = responseDictionary["Status"] as? [String: Any]
                            else {
                                throw URLError(.badServerResponse)
                            }
                            
                            guard context.verifyServerVerificationMessage(serverVerificationMessage) else {
                                throw AppleAPIError.authenticationHandshakeFailed
                            }
                            
                            guard let decryptedData = serverDictionary.decryptedCBC(context: context) else {
                                throw AppleAPIError.authenticationHandshakeFailed
                            }
                            
                            guard let decryptedDictionary = try PropertyListSerialization.propertyList(
                                from: decryptedData,
                                format: nil
                            ) as? [String: Any],
                                  let dsid = decryptedDictionary["adsid"] as? String,
                                  let idmsToken = decryptedDictionary["GsIdmsToken"] as? String
                            else {
                                throw URLError(.badServerResponse)
                            }
                            
                            context.dsid = dsid
                            
                            let authType = statusDictionary["au"] as? String
                            switch authType {
                            case "trustedDeviceSecondaryAuth":
                                guard let verificationHandler = verificationHandler else {
                                    throw AppleAPIError.requiresTwoFactorAuthentication
                                }
                                
                                self.requestTrustedDeviceTwoFactorCode(
                                    dsid: dsid,
                                    idmsToken: idmsToken,
                                    anisetteData: anisetteData,
                                    verificationHandler: verificationHandler
                                ) { result in
                                    switch result {
                                    case .failure(let error):
                                        completionHandler(nil, nil, error)
                                    case .success:
                                        self.authenticate(
                                            appleID: unsanitizedAppleID,
                                            password: password,
                                            anisetteData: anisetteData,
                                            verificationHandler: verificationHandler,
                                            completionHandler: completionHandler
                                        )
                                    }
                                }
                                
                            case "secondaryAuth":
                                guard let verificationHandler = verificationHandler else {
                                    throw AppleAPIError.requiresTwoFactorAuthentication
                                }
                                
                                self.requestSMSTwoFactorCode(
                                    dsid: dsid,
                                    idmsToken: idmsToken,
                                    anisetteData: anisetteData,
                                    verificationHandler: verificationHandler
                                ) { result in
                                    switch result {
                                    case .failure(let error):
                                        completionHandler(nil, nil, error)
                                    case .success:
                                        self.authenticate(
                                            appleID: unsanitizedAppleID,
                                            password: password,
                                            anisetteData: anisetteData,
                                            verificationHandler: verificationHandler,
                                            completionHandler: completionHandler
                                        )
                                    }
                                }
                                
                            default:
                                guard let sessionKey = decryptedDictionary["sk"] as? Data,
                                      let c = decryptedDictionary["c"] as? Data
                                else {
                                    throw URLError(.badServerResponse)
                                }
                                
                                context.sessionKey = sessionKey
                                
                                let app = "com.apple.gs.xcode.auth"
                                guard let checksum = context.makeChecksum(appName: app) else {
                                    throw AppleAPIError.authenticationHandshakeFailed
                                }
                                
                                let tokenParameters: [String: Any] = [
                                    "app": [app],
                                    "c": c,
                                    "checksum": checksum,
                                    "cpd": clientDictionary,
                                    "o": "apptokens",
                                    "t": idmsToken,
                                    "u": dsid
                                ]
                                
                                self.fetchAuthToken(
                                    app: app,
                                    parameters: tokenParameters,
                                    context: context,
                                    anisetteData: anisetteData
                                ) { result in
                                    switch result {
                                    case .failure(let error):
                                        completionHandler(nil, nil, error)
                                    case .success(let token):
                                        let session = AppleAPISession(
                                            dsid: dsid,
                                            authToken: token,
                                            anisetteData: anisetteData
                                        )
                                        
                                        self.fetchAccount(session: session) { result in
                                            switch result {
                                            case .failure(let error):
                                                completionHandler(nil, nil, error)
                                            case .success(let account):
                                                completionHandler(account, session, nil)
                                            }
                                        }
                                    }
                                }
                            }
                        } catch {
                            completionHandler(nil, nil, error)
                        }
                    }
                } catch {
                    completionHandler(nil, nil, error)
                }
            }
        } catch {
            completionHandler(nil, nil, error)
        }
    }
    
    public func sendAuthenticationRequest(
        parameters requestParameters: [String: Any],
        anisetteData: AnisetteData,
        completionHandler: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        guard let requestURL = URL(string: "https://gsa.apple.com/grandslam/GsService2") else {
            completionHandler(.failure(AppleAPIError.unknown))
            return
        }
        
        do {
            let parameters: [String: Any] = [
                "Header": ["Version": "1.0.1"],
                "Request": requestParameters
            ]
            
            let httpHeaders = [
                "Content-Type": "text/x-xml-plist",
                "X-MMe-Client-Info": anisetteData.deviceDescription,
                "Accept": "*/*",
                "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
            ]
            
            let bodyData = try PropertyListSerialization.data(
                fromPropertyList: parameters,
                format: .xml,
                options: 0
            )
            
            var request = URLRequest(url: requestURL)
            request.httpMethod = "POST"
            request.httpBody = bodyData
            httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
            
            let dataTask = self.session.dataTask(with: request) { (data, response, error) in
                do {
                    guard let data = data else {
                        throw error ?? AppleAPIError.unknown
                    }
                    
                    guard let responseDictionary = try PropertyListSerialization.propertyList(
                        from: data,
                        format: nil
                    ) as? [String: Any],
                    let dictionary = responseDictionary["Response"] as? [String: Any],
                    let status = dictionary["Status"] as? [String: Any]
                    else {
                        throw URLError(.badServerResponse)
                    }
                    
                    let errorCode = status["ec"] as? Int ?? 0
                    guard errorCode != 0 else {
                        return completionHandler(.success(dictionary))
                    }
                    
                    switch errorCode {
                    case -20101, -22406:
                        throw AppleAPIError.incorrectCredentials
                    case -22421:
                        throw AppleAPIError.invalidAnisetteData
                    default:
                        guard let errorDescription = status["em"] as? String else {
                            throw AppleAPIError.unknown
                        }
                        
                        let localizedDescription = "\(errorDescription) (\(errorCode))"
                        throw AppleAPIError.customError(code: errorCode, message: localizedDescription)
                    }
                } catch {
                    completionHandler(.failure(error))
                }
            }
            
            dataTask.resume()
        } catch {
            completionHandler(.failure(error))
        }
    }
    
    public func makeTwoFactorCodeRequest(
        url: URL,
        dsid: String,
        idmsToken: String,
        anisetteData: AnisetteData
    ) -> URLRequest {
        let identityToken = "\(dsid):\(idmsToken)"
        let encodedIdentityToken = identityToken.data(using: .utf8)?.base64EncodedString() ?? ""
        
        let httpHeaders = [
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": "Xcode",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Apple-Identity-Token": encodedIdentityToken,
            "X-Apple-I-MD-M": anisetteData.machineID,
            "X-Apple-I-MD": anisetteData.oneTimePassword,
            "X-Apple-I-MD-LU": anisetteData.localUserID,
            "X-Apple-I-MD-RINFO": "\(anisetteData.routingInfo)",
            "X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
            "X-MMe-Client-Info": anisetteData.deviceDescription,
            "X-Apple-I-Client-Time": dateFormatter.string(from: anisetteData.date),
            "X-Apple-Locale": anisetteData.locale.identifier,
            "X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation() ?? "PST"
        ]
        
        var request = URLRequest(url: url)
        httpHeaders.forEach { request.addValue($0.value, forHTTPHeaderField: $0.key) }
        
        return request
    }
}

private extension AppleAPI {
    func fetchAuthToken(app: String, parameters: [String: Any], context: GSAContext, anisetteData: AnisetteData, completionHandler: @escaping (Result<String, Error>) -> Void) {
        sendAuthenticationRequest(parameters: parameters, anisetteData: anisetteData) { result in
            do {
                let responseDictionary = try result.get()

                guard let encryptedToken = responseDictionary["et"] as? Data else { throw URLError(.badServerResponse) }
                guard let token = encryptedToken.decryptedGCM(context: context) else { throw AppleAPIError.authenticationHandshakeFailed }

                guard let tokensDictionary = try PropertyListSerialization.propertyList(from: token, format: nil) as? [String: Any] else {
                    throw URLError(.badServerResponse)
                }

                guard let appTokens = tokensDictionary["t"] as? [String: Any],
                      let tokens = appTokens[app] as? [String: Any],
                      let authToken = tokens["token"] as? String
                else { throw URLError(.badServerResponse) }

                completionHandler(.success(authToken))
            } catch {
                completionHandler(.failure(error))
            }
        }
    }

    func requestTrustedDeviceTwoFactorCode(dsid: String,
                                           idmsToken: String,
                                           anisetteData: AnisetteData,
                                           verificationHandler: @escaping (@escaping (String?) -> Void) -> Void,
                                           completionHandler: @escaping (Result<Void, Error>) -> Void) {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
        let verifyURL = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!

        let request = makeTwoFactorCodeRequest(url: requestURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)

        let requestCodeTask = session.dataTask(with: request) { data, _, error in
            do {
                guard error == nil else { throw error! }

                func responseHandler(verificationCode: String?) {
                    do {
                        guard let verificationCode = verificationCode else { throw AppleAPIError.requiresTwoFactorAuthentication }

                        var request = self.makeTwoFactorCodeRequest(url: verifyURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
                        request.allHTTPHeaderFields?["security-code"] = verificationCode
                        
                        let verifyCodeTask = self.session.dataTask(with: request) { (data, response, error) in
                            do {
                                guard let data = data else { throw error ?? AppleAPIError.unknown }
                                
                                guard let responseDictionary = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                                    throw URLError(.badServerResponse)
                                }

                                let errorCode = responseDictionary["ec"] as? Int ?? 0
                                guard errorCode != 0 else { return completionHandler(.success(())) }

                                switch errorCode {
                                case -21669: throw AppleAPIError.incorrectVerificationCode
                                default:
                                    guard let errorDescription = responseDictionary["em"] as? String else { throw AppleAPIError.unknown }
                                    
                                    let localizedDescription = errorDescription + " (\(errorCode))"
                                    throw AppleAPIError.customError(code: errorCode, message: errorDescription)
                                }
                            } catch {
                                completionHandler(.failure(error))
                            }
                        }

                        verifyCodeTask.resume()
                    } catch {
                        completionHandler(.failure(error))
                    }
                }

                verificationHandler(responseHandler)
            } catch {
                completionHandler(.failure(error))
            }
        }

        requestCodeTask.resume()
    }

    func requestSMSTwoFactorCode(dsid: String,
                                 idmsToken: String,
                                 anisetteData: AnisetteData,
                                 verificationHandler: @escaping (@escaping (String?) -> Void) -> Void,
                                 completionHandler: @escaping (Result<Void, Error>) -> Void) {
        let requestURL = URL(string: "https://gsa.apple.com/auth/verify/phone/put?mode=sms")!
        let verifyURL = URL(string: "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put")!

        var request = makeTwoFactorCodeRequest(url: requestURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
        request.httpMethod = "POST"

        do {
            let bodyXML = [
                "serverInfo": [
                    "phoneNumber.id": "1"
                ]
            ] as [String: Any]

            let bodyData = try PropertyListSerialization.data(fromPropertyList: bodyXML, format: .xml, options: 0)
            request.httpBody = bodyData
        } catch {
            completionHandler(.failure(error))
            return
        }

        let requestCodeTask = session.dataTask(with: request) { _, response, error in
            do {
                guard error == nil else { throw error! }

                func responseHandler(verificationCode: String?) {
                    do {
                        guard let verificationCode = verificationCode else { throw AppleAPIError.requiresTwoFactorAuthentication }

                        var request = self.makeTwoFactorCodeRequest(url: verifyURL, dsid: dsid, idmsToken: idmsToken, anisetteData: anisetteData)
                        request.httpMethod = "POST"

                        let bodyXML = [
                            "securityCode.code": verificationCode,
                            "serverInfo": [
                                "mode": "sms",
                                "phoneNumber.id": "1"
                            ]
                        ] as [String: Any]

                        let bodyData = try PropertyListSerialization.data(fromPropertyList: bodyXML, format: .xml, options: 0)
                        request.httpBody = bodyData

                        let verifyCodeTask = self.session.dataTask(with: request) { _, response, error in
                            do {
                                guard error == nil else { throw error! }

                                guard let httpResponse = response as? HTTPURLResponse,
                                      httpResponse.statusCode == 200,
                                      httpResponse.allHeaderFields.keys.contains("X-Apple-PE-Token")
                                else { throw AppleAPIError.incorrectVerificationCode }

                                completionHandler(.success(()))
                            } catch {
                                completionHandler(.failure(error))
                            }
                        }

                        verifyCodeTask.resume()
                    } catch {
                        completionHandler(.failure(error))
                    }
                }

                verificationHandler(responseHandler)
            } catch {
                completionHandler(.failure(error))
            }
        }

        requestCodeTask.resume()
    }
    
    func fetchAccount(session: AppleAPISession, completionHandler: @escaping (Result<Account, Error>) -> Void) {
        let url = qhURL.appendingPathComponent("viewDeveloper.action")
        
        self.sendRequestWithURL(requestURL: url, additionalParameters: nil, session: session, team: nil) { (responseDictionary, requestError) in
            do {
                guard let responseDictionary = responseDictionary else { throw requestError ?? AppleAPIError.unknown }
                

                guard let dictionary = responseDictionary["developer"] as? [String: Any] else {
                    throw AppleAPIError.unknown
                }
                
                let jsonData = try JSONSerialization.data(withJSONObject: dictionary)
                
                guard let account = try? JSONDecoder().decode(Account.self, from: jsonData) else {
                    throw AppleAPIError.unknown
                }

                completionHandler(.success(account))
            } catch {
                completionHandler(.failure(error))
            }
        }
    }
}

public enum SignError: Int, Error {
    case unknown
    case invalidApp
    case missingAppBundle
    case missingInfoPlist
    case missingProvisioningProfile
}

public enum AppleAPIError: Error {
    case unknown
    case invalidParameters
    case badServerResponse
    case incorrectCredentials
    case appSpecificPasswordRequired
    case noTeams
    case invalidDeviceID
    case deviceAlreadyRegistered
    case invalidCertificateRequest
    case certificateDoesNotExist
    case invalidAppIDName
    case invalidBundleIdentifier
    case bundleIdentifierUnavailable
    case appIDDoesNotExist
    case maximumAppIDLimitReached
    case invalidAppGroup
    case appGroupDoesNotExist
    case invalidProvisioningProfileIdentifier
    case provisioningProfileDoesNotExist
    case requiresTwoFactorAuthentication
    case incorrectVerificationCode
    case authenticationHandshakeFailed
    case invalidAnisetteData
    case customError(code: Int, message: String)
}
