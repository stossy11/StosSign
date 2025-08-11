//
//  EntitlementsParser.swift
//  StosSign
//
//  Created by Stossy11 on 25/03/2025.
//

import Foundation

public struct EntitlementsParser {
    private struct MachHeader {
        let magic: UInt32
        let cputype: Int32
        let cpusubtype: Int32
        let filetype: UInt32
        let ncmds: UInt32
        let sizeofcmds: UInt32
        let flags: UInt32
    }
    
    private struct LoadCommand {
        let cmd: UInt32
        let cmdsize: UInt32
    }
    
    private struct LinkeditDataCommand {
        let cmd: UInt32
        let cmdsize: UInt32
        let dataoff: UInt32
        let datasize: UInt32
    }
    
    private static let LC_CODE_SIGNATURE: UInt32 = 0x1D
    private static let CSSLOT_ENTITLEMENTS: UInt32 = 5

    
    static func extractEntitlements(from path: String) throws -> String {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) else {
            throw EntitlementError.fileNotFound
        }
        
        let executablePath = isDirectory.boolValue ? findExecutable(in: path) : path
        
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: executablePath)) else {
            throw EntitlementError.unableToReadFile
        }
        
        return try parseEntitlements(from: data)
    }
    
    private static func findExecutable(in bundlePath: String) -> String {
        let bundleURL = URL(fileURLWithPath: bundlePath)
        guard let bundle = Bundle(url: bundleURL) else {
            return bundlePath
        }
        
        guard let executablePath = bundle.executablePath else {
            return bundlePath
        }
        
        return executablePath
    }
    
    private static func parseEntitlements(from data: Data) throws -> String {
        guard data.count >= MemoryLayout<MachHeader>.size else {
            throw EntitlementError.invalidFileFormat
        }
        
        let headerData = data.prefix(MemoryLayout<MachHeader>.size)
        let header = headerData.withUnsafeBytes { ptr in
            ptr.baseAddress?.assumingMemoryBound(to: MachHeader.self).pointee
        }
        
        guard header?.magic == 0xfeedface || header?.magic == 0xfeedfacf else {
            throw EntitlementError.notMachOFormat
        }
        
        var offset = MemoryLayout<MachHeader>.size
        for _ in 0..<(header?.ncmds ?? 0) {
            guard offset + MemoryLayout<LoadCommand>.size <= data.count else {
                break
            }
            
            let loadCommandData = data[offset..<offset + MemoryLayout<LoadCommand>.size]
            let loadCommand = loadCommandData.withUnsafeBytes { ptr in
                ptr.baseAddress?.assumingMemoryBound(to: LoadCommand.self).pointee
            }
            
            if loadCommand?.cmd == LC_CODE_SIGNATURE {
                guard offset + MemoryLayout<LinkeditDataCommand>.size <= data.count else {
                    break
                }
                
                let linkeditData = data[offset..<offset + MemoryLayout<LinkeditDataCommand>.size]
                    .withUnsafeBytes { ptr in
                        ptr.baseAddress?.assumingMemoryBound(to: LinkeditDataCommand.self).pointee
                    }
                
                guard let entitlements = extractEntitlementsBlob(
                    from: data,
                    dataOffset: linkeditData?.dataoff ?? 0,
                    dataSize: linkeditData?.datasize ?? 0
                ) else {
                    break
                }
                
                return entitlements
            }
            
            offset += Int(loadCommand?.cmdsize ?? 0)
        }
        
        return ""
    }
    
    private static func extractEntitlementsBlob(
        from data: Data,
        dataOffset: UInt32,
        dataSize: UInt32
    ) -> String? {
        guard dataOffset + dataSize <= data.count else {
            return nil
        }
        
        let signatureBlob = data[Int(dataOffset)..<Int(dataOffset + dataSize)]
        
        guard let entitlementsString = String(
            data: signatureBlob,
            encoding: .utf8
        ) else {
            return nil
        }
        
        return entitlementsString
    }
    
    enum EntitlementError: Error {
        case fileNotFound
        case unableToReadFile
        case invalidFileFormat
        case notMachOFormat
    }
}
