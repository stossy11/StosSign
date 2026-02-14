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

    private struct CSSuperBlob {
        let magic: UInt32
        let length: UInt32
        let count: UInt32
    }

    private struct CSBlobIndex {
        let type: UInt32
        let offset: UInt32
    }

    private static let LC_CODE_SIGNATURE: UInt32 = 0x1D
    private static let CSMAGIC_EMBEDDED_SIGNATURE: UInt32 = 0xfade0cc0
    private static let CSMAGIC_EMBEDDED_ENTITLEMENTS: UInt32 = 0xfade7171


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


    private static func parseEntitlements(from data: Data) throws -> String {

        guard data.count >= MemoryLayout<MachHeader>.size else {
            throw EntitlementError.invalidFileFormat
        }

        let header = data.withUnsafeBytes {
            $0.load(as: MachHeader.self)
        }

        guard header.magic == 0xfeedface || header.magic == 0xfeedfacf else {
            throw EntitlementError.notMachOFormat
        }

        var offset = MemoryLayout<MachHeader>.size

        for _ in 0..<header.ncmds {

            let loadCommand = data[offset...].withUnsafeBytes {
                $0.load(as: LoadCommand.self)
            }

            if loadCommand.cmd == LC_CODE_SIGNATURE {

                let linkedit = data[offset...].withUnsafeBytes {
                    $0.load(as: LinkeditDataCommand.self)
                }

                return try extractEntitlementsBlob(
                    from: data,
                    dataOffset: linkedit.dataoff,
                    dataSize: linkedit.datasize
                )
            }

            offset += Int(loadCommand.cmdsize)
        }

        throw EntitlementError.invalidFileFormat
    }

    private static func extractEntitlementsBlob(
        from data: Data,
        dataOffset: UInt32,
        dataSize: UInt32
    ) throws -> String {

        let start = Int(dataOffset)
        let end = start + Int(dataSize)

        guard end <= data.count else {
            throw EntitlementError.invalidFileFormat
        }

        let superBlob = data[start...].withUnsafeBytes {
            $0.load(as: CSSuperBlob.self)
        }

        let magic = CFSwapInt32(superBlob.magic)
        guard magic == CSMAGIC_EMBEDDED_SIGNATURE else {
            throw EntitlementError.invalidFileFormat
        }

        let count = CFSwapInt32(superBlob.count)
        let indexOffset = start + MemoryLayout<CSSuperBlob>.size

        for i in 0..<count {

            let entryOffset = indexOffset + Int(i) * MemoryLayout<CSBlobIndex>.size

            let blobIndex = data[entryOffset...].withUnsafeBytes {
                $0.load(as: CSBlobIndex.self)
            }

            let blobOffset = start + Int(CFSwapInt32(blobIndex.offset))

            let blobMagic = data[blobOffset...].withUnsafeBytes {
                $0.load(as: UInt32.self)
            }

            if CFSwapInt32(blobMagic) == CSMAGIC_EMBEDDED_ENTITLEMENTS {

                let length = data[(blobOffset + 4)..<data.count].withUnsafeBytes {
                    $0.load(as: UInt32.self)
                }

                let blobLength = Int(CFSwapInt32(length))
                let plistStart = blobOffset + 8
                let plistEnd = blobOffset + blobLength

                let plistData = data[plistStart..<plistEnd]

                guard let entitlements = String(data: plistData, encoding: .utf8) else {
                    throw EntitlementError.invalidFileFormat
                }

                return entitlements
            }
        }

        throw EntitlementError.invalidFileFormat
    }


    private static func findExecutable(in bundlePath: String) -> String {
        let bundleURL = URL(fileURLWithPath: bundlePath)
        guard let bundle = Bundle(url: bundleURL),
              let executablePath = bundle.executablePath else {
            return bundlePath
        }
        return executablePath
    }

    enum EntitlementError: Error {
        case fileNotFound
        case unableToReadFile
        case invalidFileFormat
        case notMachOFormat
    }
}
