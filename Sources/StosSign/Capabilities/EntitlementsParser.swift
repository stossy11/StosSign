//
//  EntitlementsParser.swift
//  StosSign
//
//  Created by Stossy11 on 25/03/2025.
//

import Foundation
import MachO

class EntitlementsParser {

    enum Error: Swift.Error {
        case binaryOpeningError
        case unknownBinaryFormat
        case codeSignatureCommandMissing
        case signatureReadingError
        case unsupportedFatBinary
        case invalidBundleURL
        case missingExecutablePath

        var localizedDescription: String {
            switch self {
            case .binaryOpeningError:
                return "Error while opening application binary for reading"
            case .unknownBinaryFormat:
                return "The binary format is not supported"
            case .codeSignatureCommandMissing:
                return "Unable to find code signature load command"
            case .signatureReadingError:
                return "Signature reading error occurred"
            case .unsupportedFatBinary:
                return "Fat application binaries are unsupported"
            case .invalidBundleURL:
                return "Invalid bundle URL"
            case .missingExecutablePath:
                return "Missing executable path from bundle"
            }
        }
    }

    public static func extractEntitlements(from path: String) throws -> String {
        guard let bundle = Bundle(url: URL(fileURLWithPath: path)) else {
            throw Error.invalidBundleURL
        }
        guard let execPath = bundle.executablePath else {
            throw Error.missingExecutablePath
        }

        let reader = try EntitlementsParser(execPath)
        let entitlements = try reader.readEntitlements()
        return entitlements
    }

    private struct CSSuperBlob {
        var magic: UInt32
        var lentgh: UInt32
        var count: UInt32
    }

    private struct CSBlob {
        var type: UInt32
        var offset: UInt32
    }

    private struct CSMagic {
        static let embeddedSignature: UInt32 = 0xfade0cc0
        static let embededEntitlements: UInt32 = 0xfade7171
    }

    private enum BinaryType {
        struct HeaderData {
            let headerSize: Int
            let commandCount: Int
        }
        case singleArch(headerInfo: HeaderData)
        case fat(header: fat_header)
    }

    private class ApplicationBinary {
        private let handle: FileHandle

        init?(_ path: String) {
            guard let binaryHandle = FileHandle(forReadingAtPath: path) else {
                return nil
            }
            handle = binaryHandle
        }

        var currentOffset: UInt64 { handle.offsetInFile }

        func seek(to offset: UInt64) {
            handle.seek(toFileOffset: offset)
        }

        func read<T>() -> T {
            handle.readData(ofLength: MemoryLayout<T>.size).withUnsafeBytes( { $0.load(as: T.self) })
        }

        func readData(ofLength length: Int) -> Data {
            handle.readData(ofLength: length)
        }

        deinit {
            handle.closeFile()
        }
    }

    private let binary: ApplicationBinary

    init(_ binaryPath: String) throws {
        guard let binary = ApplicationBinary(binaryPath) else {
            throw Error.binaryOpeningError
        }
        self.binary = binary
    }

    private func getBinaryType(fromSliceStartingAt offset: UInt64 = 0) -> BinaryType? {
        binary.seek(to: offset)
        let header: mach_header = binary.read()
        let commandCount = Int(header.ncmds)
        switch header.magic {
        case MH_MAGIC:
            let data = BinaryType.HeaderData(headerSize: MemoryLayout<mach_header>.size,
                                             commandCount: commandCount)
            return .singleArch(headerInfo: data)
        case MH_MAGIC_64:
            let data = BinaryType.HeaderData(headerSize: MemoryLayout<mach_header_64>.size,
                                             commandCount: commandCount)
            return .singleArch(headerInfo: data)
        default:
            binary.seek(to: 0)
            let fatHeader: fat_header = binary.read()
            return CFSwapInt32(fatHeader.magic) == FAT_MAGIC ? .fat(header: fatHeader) : nil
        }
    }

    func readEntitlements() throws -> String {
        switch getBinaryType() {
        case .singleArch(let headerInfo):
            let headerSize = headerInfo.headerSize
            let commandCount = headerInfo.commandCount
            return try readEntitlementsFromBinarySlice(startingAt: headerSize, cmdCount: commandCount)
        case .fat:
            return try readEntitlementsFromFatBinary()
        case .none:
            throw Error.unknownBinaryFormat
        }
    }

    private func readEntitlementsFromBinarySlice(startingAt offset: Int, cmdCount: Int) throws -> String {
        binary.seek(to: UInt64(offset))
        for _ in 0..<cmdCount {
            let command: load_command = binary.read()
            if command.cmd == LC_CODE_SIGNATURE {
                let signatureOffset: UInt32 = binary.read()
                return try readEntitlementsFromSignature(startingAt: signatureOffset)
            }
            binary.seek(to: binary.currentOffset + UInt64(command.cmdsize - UInt32(MemoryLayout<load_command>.size)))
        }
        throw Error.codeSignatureCommandMissing
    }

    private func readEntitlementsFromFatBinary() throws -> String {
        throw Error.unsupportedFatBinary
    }

    private func readEntitlementsFromSignature(startingAt offset: UInt32) throws -> String {
        binary.seek(to: UInt64(offset))
        let metaBlob: CSSuperBlob = binary.read()
        if CFSwapInt32(metaBlob.magic) == CSMagic.embeddedSignature {
            let metaBlobSize = UInt32(MemoryLayout<CSSuperBlob>.size)
            let blobSize = UInt32(MemoryLayout<CSBlob>.size)
            let itemCount = CFSwapInt32(metaBlob.count)
            for index in 0..<itemCount {
                let readOffset = UInt64(offset + metaBlobSize + index * blobSize)
                binary.seek(to: readOffset)
                let blob: CSBlob = binary.read()
                binary.seek(to: UInt64(offset + CFSwapInt32(blob.offset)))
                let blobMagic = CFSwapInt32(binary.read())
                if blobMagic == CSMagic.embededEntitlements {
                    let signatureLength = CFSwapInt32(binary.read())
                    let signatureData = binary.readData(ofLength: Int(signatureLength) - 8)
                    guard let dict = try? PropertyListSerialization.propertyList(from: signatureData, options: [], format: nil) as? [String: Any],
                        let xmlData = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0),
                        let xmlString = String(data: xmlData, encoding: .utf8) else {
                        return ""
                    }

                    return xmlString
                }
            }
        }
        throw Error.signatureReadingError
    }
}
