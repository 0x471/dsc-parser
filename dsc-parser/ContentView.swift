import SwiftUI
import NFCPassportReader
import Security
import CryptoKit

// MARK: - Certificate Models

struct CertificateInfo {
    let commonName: String
    let organization: String
    let organizationalUnit: String
    let country: String
    let serialNumber: String
    let validFrom: Date
    let validUntil: Date
    let publicKeyAlgorithm: String
    let publicKeySize: String
    let signatureAlgorithm: String
    let fullIssuerDN: String
    let fullSubjectDN: String
    let authorityKeyIdentifier: String?
    let subjectKeyIdentifier: String?
}

struct CSCAInfo {
    let country: String
    let countryCode: String
    let organization: String
    let organizationalUnit: String
    let commonName: String
    let fullDistinguishedName: String
    let authorityKeyIdentifier: String?
    
    var displayName: String {
        if !commonName.isEmpty {
            return commonName
        } else if !organization.isEmpty {
            return organization
        }
        return "Unknown CSCA"
    }
    
    var flag: String {
        let base: UInt32 = 127397
        var emoji = ""
        for scalar in countryCode.uppercased().unicodeScalars {
            if let flagScalar = UnicodeScalar(base + scalar.value) {
                emoji.append(String(flagScalar))
            }
        }
        return emoji.isEmpty ? "🏳️" : emoji
    }
}

// MARK: - MRZ Handler (Smart Auto-Detection)

class MRZHandler {
    
    static func generateMRZKeys(documentNumber: String, birthDate: String, expiryDate: String) -> [String] {
        var keys: [String] = []
        
        let docNum = documentNumber.uppercased().trimmingCharacters(in: .whitespaces)
        
        keys.append(constructMRZKey(docNum, birthDate, expiryDate))
        
        if docNum.count < 9 {
            let paddedDoc = docNum.padding(toLength: 9, withPad: "<", startingAt: 0)
            keys.append(constructMRZKey(paddedDoc, birthDate, expiryDate))
        }
        
        let cleanedDoc = docNum.filter { $0.isLetter || $0.isNumber }
        if cleanedDoc != docNum {
            keys.append(constructMRZKey(cleanedDoc, birthDate, expiryDate))
        }
        
        return Array(Set(keys))
    }
    
    private static func constructMRZKey(_ docNumber: String, _ birthDate: String, _ expiryDate: String) -> String {
        let docCheck = calculateCheckDigit(docNumber)
        let birthCheck = calculateCheckDigit(birthDate)
        let expiryCheck = calculateCheckDigit(expiryDate)
        
        return docNumber + docCheck + birthDate + birthCheck + expiryDate + expiryCheck
    }
    
    static func calculateCheckDigit(_ input: String) -> String {
        let weights = [7, 3, 1]
        var sum = 0
        
        for (index, char) in input.enumerated() {
            let value: Int
            if char.isNumber {
                value = Int(String(char))!
            } else if char == "<" {
                value = 0
            } else if char.isLetter {
                value = Int(char.uppercased().unicodeScalars.first!.value) - 55
            } else {
                value = 0
            }
            sum += value * weights[index % 3]
        }
        
        return String(sum % 10)
    }
    
    static func detectDocumentType(documentNumber: String) -> String {
        let cleaned = documentNumber.uppercased().trimmingCharacters(in: .whitespaces)
        
        if cleaned.count >= 7 && cleaned.count <= 9 {
            let hasLetters = cleaned.contains(where: { $0.isLetter })
            let hasNumbers = cleaned.contains(where: { $0.isNumber })
            
            if hasLetters && hasNumbers {
                return "passport"
            } else if !hasLetters && hasNumbers {
                return "id_card"
            }
        }
        
        return "document"
    }
}

// MARK: - Certificate Parser
class CertificateParser {
    
    static func extractDSCFromSOD(_ sodData: Data) -> SecCertificate? {
        var offset = 0
        let dataBytes = [UInt8](sodData)
        
        while offset < dataBytes.count - 4 {
            if dataBytes[offset] == 0x30 && dataBytes[offset + 1] == 0x82 {
                let lengthHigh = Int(dataBytes[offset + 2])
                let lengthLow = Int(dataBytes[offset + 3])
                let certLength = (lengthHigh << 8) | lengthLow
                
                if certLength > 500 && certLength < 8000 && offset + certLength + 4 <= dataBytes.count {
                    let certData = sodData.subdata(in: offset..<(offset + certLength + 4))
                    
                    if let certificate = SecCertificateCreateWithData(nil, certData as CFData) {
                        print("DSC certificate found at offset \(offset), size: \(certLength) bytes")
                        return certificate
                    }
                }
            }
            offset += 1
        }
        
        print("Could not extract DSC from SOD")
        return nil
    }
    
    static func parseCertificate(_ certificate: SecCertificate) -> CertificateInfo? {
        let certData = SecCertificateCopyData(certificate) as Data
        
        guard let parsed = parseX509Certificate(certData) else {
            print("Failed to parse certificate")
            return nil
        }
        
        let (pubKeyAlg, pubKeySize) = getPublicKeyInfo(certificate)
        
        return CertificateInfo(
            commonName: parsed.issuerCN,
            organization: parsed.issuerOrg,
            organizationalUnit: parsed.issuerOU,
            country: parsed.issuerCountry,
            serialNumber: parsed.serialNumber,
            validFrom: parsed.notBefore,
            validUntil: parsed.notAfter,
            publicKeyAlgorithm: pubKeyAlg,
            publicKeySize: pubKeySize,
            signatureAlgorithm: parsed.signatureAlgorithm,
            fullIssuerDN: parsed.issuerDN,
            fullSubjectDN: parsed.subjectDN,
            authorityKeyIdentifier: parsed.authorityKeyIdentifier,
            subjectKeyIdentifier: parsed.subjectKeyIdentifier
        )
    }
    
    static func extractCSCA(from dscInfo: CertificateInfo) -> CSCAInfo {
        return CSCAInfo(
            country: getCountryName(from: dscInfo.country),
            countryCode: dscInfo.country,
            organization: dscInfo.organization,
            organizationalUnit: dscInfo.organizationalUnit,
            commonName: dscInfo.commonName,
            fullDistinguishedName: dscInfo.fullIssuerDN,
            authorityKeyIdentifier: dscInfo.authorityKeyIdentifier
        )
    }
    
    // MARK: - ASN.1 Parser
    
    struct ParsedCertificate {
        var serialNumber: String = ""
        var issuerDN: String = ""
        var issuerCountry: String = ""
        var issuerOrg: String = ""
        var issuerOU: String = ""
        var issuerCN: String = ""
        var subjectDN: String = ""
        var notBefore: Date = Date()
        var notAfter: Date = Date()
        var signatureAlgorithm: String = ""
        var authorityKeyIdentifier: String?
        var subjectKeyIdentifier: String?
    }
    
    private static func parseX509Certificate(_ data: Data) -> ParsedCertificate? {
        var result = ParsedCertificate()
        let bytes = [UInt8](data)
        
        guard bytes.count > 10 else { return nil }
        
        var offset = 0
        guard bytes[offset] == 0x30 else { return nil }
        offset += 1
        let (_, nextOffset) = parseLength(bytes, offset)
        offset = nextOffset
        
        guard bytes[offset] == 0x30 else { return nil }
        offset += 1
        let (_, tbsStart) = parseLength(bytes, offset)
        offset = tbsStart
        
        if bytes[offset] == 0xA0 {
            let (versionLength, _) = parseLength(bytes, offset + 1)
            offset += 2 + versionLength
        }
        
        if bytes[offset] == 0x02 {
            offset += 1
            let (serialLength, serialStart) = parseLength(bytes, offset)
            offset = serialStart
            result.serialNumber = bytes[offset..<(offset + serialLength)]
                .map { String(format: "%02X", $0) }
                .joined()
            offset += serialLength
        }
        
        if bytes[offset] == 0x30 {
            result.signatureAlgorithm = parseAlgorithmIdentifier(bytes, offset)
            let (algLength, algStart) = parseLength(bytes, offset + 1)
            offset = algStart + algLength
        }
        
        if bytes[offset] == 0x30 {
            let (issuerDN, issuerComponents) = parseDistinguishedName(bytes, offset)
            result.issuerDN = issuerDN
            result.issuerCountry = issuerComponents["C"] ?? ""
            result.issuerOrg = issuerComponents["O"] ?? ""
            result.issuerOU = issuerComponents["OU"] ?? ""
            result.issuerCN = issuerComponents["CN"] ?? ""
            
            let (issuerLength, issuerStart) = parseLength(bytes, offset + 1)
            offset = issuerStart + issuerLength
        }
        
        if bytes[offset] == 0x30 {
            offset += 1
            let (_, validityStart) = parseLength(bytes, offset)
            offset = validityStart
            
            if bytes[offset] == 0x17 || bytes[offset] == 0x18 {
                result.notBefore = parseTime(bytes, offset) ?? Date()
                let (timeLength, timeStart) = parseLength(bytes, offset + 1)
                offset = timeStart + timeLength
            }
            
            if bytes[offset] == 0x17 || bytes[offset] == 0x18 {
                result.notAfter = parseTime(bytes, offset) ?? Date()
                let (timeLength, timeStart) = parseLength(bytes, offset + 1)
                offset = timeStart + timeLength
            }
        }
        
        if bytes[offset] == 0x30 {
            let (subjectDN, _) = parseDistinguishedName(bytes, offset)
            result.subjectDN = subjectDN
        }
        
        result.authorityKeyIdentifier = extractKeyIdentifier(bytes, oid: "551D23")
        result.subjectKeyIdentifier = extractKeyIdentifier(bytes, oid: "551D0E")
        
        return result
    }
    
    private static func parseLength(_ bytes: [UInt8], _ offset: Int) -> (Int, Int) {
        guard offset < bytes.count else { return (0, offset) }
        
        let firstByte = bytes[offset]
        
        if firstByte < 0x80 {
            return (Int(firstByte), offset + 1)
        } else {
            let numBytes = Int(firstByte & 0x7F)
            var length = 0
            var currentOffset = offset + 1
            
            for _ in 0..<numBytes {
                guard currentOffset < bytes.count else { break }
                length = (length << 8) | Int(bytes[currentOffset])
                currentOffset += 1
            }
            
            return (length, currentOffset)
        }
    }
    
    private static func parseDistinguishedName(_ bytes: [UInt8], _ offset: Int) -> (String, [String: String]) {
        var components: [String: String] = [:]
        var dnString = ""
        var currentOffset = offset
        
        guard bytes[currentOffset] == 0x30 else { return ("", [:]) }
        currentOffset += 1
        let (dnLength, dnStart) = parseLength(bytes, currentOffset)
        currentOffset = dnStart
        let dnEnd = currentOffset + dnLength
        
        while currentOffset < dnEnd && currentOffset < bytes.count - 5 {
            if bytes[currentOffset] == 0x31 {
                currentOffset += 1
                let (_, setStart) = parseLength(bytes, currentOffset)
                currentOffset = setStart
                
                if bytes[currentOffset] == 0x30 {
                    currentOffset += 1
                    let (_, seqStart) = parseLength(bytes, currentOffset)
                    currentOffset = seqStart
                    
                    if bytes[currentOffset] == 0x06 {
                        currentOffset += 1
                        let (oidLength, oidStart) = parseLength(bytes, currentOffset)
                        currentOffset = oidStart
                        let oidBytes = bytes[currentOffset..<min(currentOffset + oidLength, bytes.count)]
                        let oidName = oidToAttributeName(oidBytes)
                        currentOffset += oidLength
                        
                        if currentOffset < bytes.count {
                            let valueTag = bytes[currentOffset]
                            if valueTag >= 0x0C && valueTag <= 0x16 {
                                currentOffset += 1
                                let (valueLength, valueStart) = parseLength(bytes, currentOffset)
                                currentOffset = valueStart
                                
                                if let value = String(bytes: bytes[currentOffset..<min(currentOffset + valueLength, bytes.count)], encoding: .utf8) {
                                    components[oidName] = value
                                    if !dnString.isEmpty { dnString += ", " }
                                    dnString += "\(oidName)=\(value)"
                                }
                                currentOffset += valueLength
                            } else {
                                currentOffset += 1
                            }
                        }
                    }
                }
            } else {
                currentOffset += 1
            }
        }
        
        return (dnString, components)
    }
    
    private static func oidToAttributeName(_ oidBytes: ArraySlice<UInt8>) -> String {
        let oidHex = oidBytes.map { String(format: "%02X", $0) }.joined()
        // TODO: add more OIDs
        switch oidHex {
        case "550406": return "C"
        case "55040A": return "O"
        case "55040B": return "OU"
        case "550403": return "CN"
        case "550405": return "SN"
        case "550408": return "ST"
        case "550407": return "L"
        default: return "OID(\(oidHex))"
        }
    }
    
    private static func parseTime(_ bytes: [UInt8], _ offset: Int) -> Date? {
        let tag = bytes[offset]
        guard tag == 0x17 || tag == 0x18 else { return nil }
        
        var currentOffset = offset + 1
        let (timeLength, timeStart) = parseLength(bytes, currentOffset)
        currentOffset = timeStart
        
        guard let timeString = String(bytes: bytes[currentOffset..<(currentOffset + timeLength)], encoding: .ascii) else {
            return nil
        }
        
        let formatter = DateFormatter()
        
        if tag == 0x17 {
            formatter.dateFormat = "yyMMddHHmmss'Z'"
            formatter.timeZone = TimeZone(identifier: "UTC")
        } else {
            formatter.dateFormat = "yyyyMMddHHmmss'Z'"
            formatter.timeZone = TimeZone(identifier: "UTC")
        }
        
        return formatter.date(from: timeString)
    }
    
    private static func parseAlgorithmIdentifier(_ bytes: [UInt8], _ offset: Int) -> String {
        guard bytes[offset] == 0x30 else { return "Unknown" }
        var currentOffset = offset + 1
        let (_, algStart) = parseLength(bytes, currentOffset)
        currentOffset = algStart
        
        if bytes[currentOffset] == 0x06 {
            currentOffset += 1
            let (oidLength, oidStart) = parseLength(bytes, currentOffset)
            currentOffset = oidStart
            let oidHex = bytes[currentOffset..<(currentOffset + oidLength)]
                .map { String(format: "%02x", $0) }
                .joined()
            
            return oidToAlgorithmName(oidHex)
        }
        
        return "Unknown"
    }
    
    private static func oidToAlgorithmName(_ oidHex: String) -> String {
        // TODO: add more OIDs
        switch oidHex {
        case "2a864886f70d01010b": return "SHA-256 with RSA"
        case "2a864886f70d01010a": return "RSASSA-PSS"
        case "2a864886f70d010105": return "SHA-1 with RSA"
        case "2a864886f70d01010d": return "SHA-512 with RSA"
        case "2a864886f70d01010c": return "SHA-384 with RSA"
        case "2a8648ce3d040302": return "ECDSA with SHA-256"
        case "2a8648ce3d040303": return "ECDSA with SHA-384"
        case "2a8648ce3d040304": return "ECDSA with SHA-512"
        default: return "Unknown (\(oidHex))"
        }
    }
    
    private static func extractKeyIdentifier(_ bytes: [UInt8], oid: String) -> String? {
        let hexString = bytes.map { String(format: "%02x", $0) }.joined()
        
        guard let range = hexString.range(of: oid.lowercased()) else { return nil }
        
        let startIndex = hexString.index(range.upperBound, offsetBy: 0)
        guard startIndex < hexString.endIndex else { return nil }
        
        let remainingHex = String(hexString[startIndex...])
        
        if let keyIdRange = remainingHex.range(of: "0414") {
            let keyStart = remainingHex.index(keyIdRange.upperBound, offsetBy: 0)
            let keyEnd = remainingHex.index(keyStart, offsetBy: min(40, remainingHex.distance(from: keyStart, to: remainingHex.endIndex)))
            return String(remainingHex[keyStart..<keyEnd]).uppercased()
        }
        
        return nil
    }
    
    private static func getPublicKeyInfo(_ cert: SecCertificate) -> (String, String) {
        guard let publicKey = SecCertificateCopyKey(cert) else {
            return ("Unknown", "Unknown")
        }
        
        guard let attributes = SecKeyCopyAttributes(publicKey) as? [CFString: Any] else {
            return ("Unknown", "Unknown")
        }
        
        let keyType = attributes[kSecAttrKeyType] as? String ?? "Unknown"
        let keySize = attributes[kSecAttrKeySizeInBits] as? Int ?? 0
        
        let algorithm: String
        if keyType.contains("RSA") || keyType as CFString == kSecAttrKeyTypeRSA {
            algorithm = "RSA"
        } else if keyType.contains("EC") || keyType as CFString == kSecAttrKeyTypeEC || keyType as CFString == kSecAttrKeyTypeECSECPrimeRandom {
            algorithm = "ECDSA"
        } else {
            algorithm = keyType
        }
        
        return (algorithm, "\(keySize) bits")
    }
    
    private static func getCountryName(from code: String) -> String {
        // TODO: add more countries
        let countries: [String: String] = [
            "TR": "Turkey", "US": "United States", "GB": "United Kingdom",
            "DE": "Germany", "FR": "France", "IT": "Italy", "ES": "Spain",
            "NL": "Netherlands", "BE": "Belgium", "AT": "Austria", "CH": "Switzerland",
            "SE": "Sweden", "NO": "Norway", "DK": "Denmark", "FI": "Finland",
            "PL": "Poland", "CZ": "Czech Republic", "GR": "Greece", "PT": "Portugal",
            "IE": "Ireland", "RO": "Romania", "BG": "Bulgaria", "HR": "Croatia",
            "CA": "Canada", "AU": "Australia", "NZ": "New Zealand", "JP": "Japan",
            "KR": "South Korea", "CN": "China", "IN": "India", "BR": "Brazil",
            "MX": "Mexico", "AR": "Argentina", "CL": "Chile", "ZA": "South Africa",
            "EG": "Egypt", "IL": "Israel", "SA": "Saudi Arabia", "AE": "UAE",
            "RU": "Russia", "UA": "Ukraine", "SG": "Singapore", "MY": "Malaysia",
            "TH": "Thailand", "ID": "Indonesia", "PH": "Philippines", "VN": "Vietnam"
        ]
        return countries[code.uppercased()] ?? code
    }
}

// MARK: - Share Sheet
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    
    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(activityItems: items, applicationActivities: nil)
        return controller
    }
    
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// MARK: - Main Content View
struct ContentView: View {
    @State private var documentNumber = ""
    @State private var birthDate = ""
    @State private var expiryDate = ""
    
    @State private var statusMessage = "Enter your document details to begin"
    @State private var isScanning = false
    @State private var scanProgress = 0
    
    @State private var cscaInfo: CSCAInfo?
    @State private var dscInfo: CertificateInfo?
    @State private var documentInfo = ""
    @State private var allDataGroups = ""
    @State private var certificateFingerprint = ""
    @State private var documentExpiryDate = ""
    
    @State private var savedFiles: [URL] = []
    @State private var showShareSheet = false
    
    private var isInputValid: Bool {
        let docNumValid = documentNumber.count >= 7 && documentNumber.count <= 9
        let birthValid = birthDate.count == 6 && birthDate.allSatisfy({ $0.isNumber })
        let expiryValid = expiryDate.count == 6 && expiryDate.allSatisfy({ $0.isNumber })
        return docNumValid && birthValid && expiryValid
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                VStack(spacing: 4) {
                    Text("DSC Parser")
                        .font(.system(size: 34, weight: .bold))
                    
                    Text("Extract information and certificate authority from e-documents")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(.top)
                
                InstructionsCard()
                
                VStack(spacing: 16) {
                    SmartInputField(
                        icon: "number",
                        title: "Document Number",
                        text: $documentNumber,
                        placeholder: "e.g., A12345678",
                        isValid: documentNumber.count >= 7 && documentNumber.count <= 9,
                        counter: "\(documentNumber.count)/9"
                    )
                    
                    SmartInputField(
                        icon: "calendar",
                        title: "Birth Date",
                        text: $birthDate,
                        placeholder: "YYMMDD (e.g., 900315)",
                        keyboardType: .numberPad,
                        isValid: birthDate.count == 6,
                        counter: "\(birthDate.count)/6"
                    )
                    
                    SmartInputField(
                        icon: "calendar.badge.clock",
                        title: "Expiry Date",
                        text: $expiryDate,
                        placeholder: "YYMMDD (e.g., 301231)",
                        keyboardType: .numberPad,
                        isValid: expiryDate.count == 6,
                        counter: "\(expiryDate.count)/6"
                    )
                }
                .padding(.horizontal)
                
                if !documentNumber.isEmpty || !birthDate.isEmpty || !expiryDate.isEmpty {
                    ValidationBadge(isValid: isInputValid)
                }
                
                ScanButton(
                    isScanning: isScanning,
                    isEnabled: isInputValid,
                    action: scanDocument
                )
                
                if !statusMessage.isEmpty {
                    StatusCard(message: statusMessage, isScanning: isScanning)
                }
                
                if let csca = cscaInfo, let dsc = dscInfo {
                    VStack(spacing: 16) {
                        Divider()
                            .padding(.vertical)
                        
                        CSCAResultView(
                            csca: csca,
                            dsc: dsc,
                            fingerprint: certificateFingerprint,
                            docExpiry: documentExpiryDate
                        )
                        
                        if !documentInfo.isEmpty {
                            DocumentInfoCard(info: documentInfo)
                        }
                        
                        if !allDataGroups.isEmpty {
                            DataGroupsCard(groups: allDataGroups)
                        }
                    }
                }
                
                if !savedFiles.isEmpty {
                    ExportButton(fileCount: savedFiles.count) {
                        let fileManager = FileManager.default
                        let existingFiles = savedFiles.filter { fileManager.fileExists(atPath: $0.path) }
                        
                        if existingFiles.count == savedFiles.count {
                            showShareSheet = true
                        } else {
                            print("[WARN] Some files no longer exist: \(savedFiles.count - existingFiles.count) missing")
                            savedFiles = existingFiles
                            if !existingFiles.isEmpty {
                                showShareSheet = true
                            }
                        }
                    }
                }
            }
            .padding()
        }
        .sheet(isPresented: $showShareSheet) {
            if !savedFiles.isEmpty {
                let fileManager = FileManager.default
                let validFiles = savedFiles.filter { fileManager.fileExists(atPath: $0.path) }
                
                if !validFiles.isEmpty {
                    ShareSheet(items: validFiles)
                } else {
                    Text("Files not found")
                        .padding()
                }
            }
        }
    }
    
    func clearResults() {
        statusMessage = "Enter your document details to begin"
        cscaInfo = nil
        dscInfo = nil
        documentInfo = ""
        allDataGroups = ""
        certificateFingerprint = ""
        documentExpiryDate = ""
        savedFiles = []
        scanProgress = 0
    }
    
    func scanDocument() {
        isScanning = true
        statusMessage = "Preparing to scan..."
        clearResults()
        
        guard isInputValid else {
            statusMessage = "Please check all fields are correct"
            isScanning = false
            return
        }
        
        let mrzKeys = MRZHandler.generateMRZKeys(
            documentNumber: documentNumber,
            birthDate: birthDate,
            expiryDate: expiryDate
        )
        
        print("Generated \(mrzKeys.count) MRZ key(s) to try:")
        mrzKeys.enumerated().forEach { index, key in
            print("   \(index + 1). \(key)")
        }
        
        Task {
            await attemptScanWithKeys(mrzKeys)
        }
    }
    
    func attemptScanWithKeys(_ keys: [String]) async {
        for (index, mrzKey) in keys.enumerated() {
            await MainActor.run {
                statusMessage = "Attempting scan (\(index + 1)/\(keys.count))..."
            }
            
            print("Trying MRZ key: \(mrzKey)")
            
            let success = await attemptSingleScan(mrzKey: mrzKey)
            
            if success {
                print("Scan successful with key: \(mrzKey)")
                return
            } else {
                print("Failed with key: \(mrzKey)")
            }
        }
        
        await MainActor.run {
            statusMessage = """
            Could not read document
            
            Please verify:
            - Document number is correct
            - Dates are in YYMMDD format
            - NFC is enabled
            - Remove phone case
            
            Try checking the MRZ line on your document.
            """
            isScanning = false
        }
    }
    
    func attemptSingleScan(mrzKey: String) async -> Bool {
        do {
            let passportReader = PassportReader()
            
            let dataGroups: [DataGroupId] = [
                .COM, .DG1, .DG11, .DG12, .DG15, .SOD
            ]
            
            let passport = try await passportReader.readPassport(
                mrzKey: mrzKey,
                tags: dataGroups
            )
            
            await MainActor.run {
                processPassportData(passport)
            }
            
            return true
            
        } catch NFCPassportReaderError.ResponseError(let msg, let sw1, let sw2) {
            if (sw1 == 0x63 && sw2 == 0x00) || (sw1 == 0x69 && sw2 == 0x82) {
                return false
            }
            
            await MainActor.run {
                handleNFCError(message: msg, sw1: sw1, sw2: sw2)
            }
            return false
            
        } catch {
            return false
        }
    }
    
    func handleNFCError(message: String, sw1: UInt8, sw2: UInt8) {
        var errorMsg = "Error: \(message)\n\n"
        
        switch (sw1, sw2) {
        case (0x6A, 0x82):
            errorMsg += "Some data groups not found (normal)"
        default:
            errorMsg += """
            Try:
            - Re-check your input
            - Ensure NFC is enabled
            - Remove phone case
            - Hold phone steady
            """
        }
        
        statusMessage = errorMsg
        isScanning = false
    }
    
    func processPassportData(_ passport: NFCPassportModel) {
        var foundDataGroups: [String] = []
        var sodData: Data?
        
        print("Processing document data...")
        
        documentInfo = buildDocumentInfo(passport)
        
        let dataGroups = passport.dataGroupsRead
        
        for (groupId, dataGroup) in dataGroups {
            let data = Data(dataGroup.data)
            let groupName = getDataGroupName(groupId)
            foundDataGroups.append("\(groupName): \(data.count) bytes")
            
            if groupId == .SOD {
                sodData = data
            }
        }
        
        allDataGroups = foundDataGroups.sorted().joined(separator: "\n")
        
        if let sod = sodData {
            extractCSCAFromSOD(sod)
        } else {
            statusMessage = "Document read\nCertificate data not available"
            isScanning = false
        }
    }
    
    func extractCSCAFromSOD(_ sodData: Data) {
        print("Extracting CSCA from SOD...")
        
        guard let dscCertificate = CertificateParser.extractDSCFromSOD(sodData) else {
            statusMessage = "Document scanned\nCould not extract certificate"
            isScanning = false
            return
        }
        
        guard let parsedDSC = CertificateParser.parseCertificate(dscCertificate) else {
            statusMessage = "Certificate found\nCould not parse certificate"
            isScanning = false
            return
        }
        
        let extractedCSCA = CertificateParser.extractCSCA(from: parsedDSC)
        
        let certData = SecCertificateCopyData(dscCertificate) as Data
        certificateFingerprint = calculateSHA256Fingerprint(certData)
        
        documentExpiryDate = formatExpiryDate(expiryDate)
        
        print("CSCA extracted:")
        print("   Country: \(extractedCSCA.country)")
        print("   Organization: \(extractedCSCA.organization)")
        print("   Fingerprint: \(certificateFingerprint)")
        
        self.cscaInfo = extractedCSCA
        self.dscInfo = parsedDSC
        
        saveCertificateData(sodData, dsc: parsedDSC, csca: extractedCSCA)
        
        if !savedFiles.isEmpty {
            statusMessage = "Success, data extracted!"
        }
        
        isScanning = false
    }
    
    func calculateSHA256Fingerprint(_ data: Data) -> String {
        let hash = SHA256.hash(data: data)
        return hash.map { String(format: "%02X", $0) }.joined()
    }
    
    func formatExpiryDate(_ yymmdd: String) -> String {
        guard yymmdd.count == 6 else { return "" }
        let yy = String(yymmdd.prefix(2))
        let mm = String(yymmdd.dropFirst(2).prefix(2))
        let dd = String(yymmdd.suffix(2))
        
        let yyyy = Int(yy)! <= 30 ? "20\(yy)" : "19\(yy)"
        
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd"
        if let date = dateFormatter.date(from: "\(yyyy)-\(mm)-\(dd)") {
            dateFormatter.dateStyle = .medium
            return dateFormatter.string(from: date)
        }
        return "\(yyyy)-\(mm)-\(dd)"
    }
    
    func buildDocumentInfo(_ passport: NFCPassportModel) -> String {
        var info = ""
        if !passport.documentType.isEmpty { info += "Type: \(passport.documentType)\n" }
        if !passport.documentNumber.isEmpty { info += "Number: \(passport.documentNumber)\n" }
        if !passport.firstName.isEmpty || !passport.lastName.isEmpty {
            info += "Name: \(passport.firstName) \(passport.lastName)\n"
        }
        if !passport.nationality.isEmpty { info += "Nationality: \(passport.nationality)\n" }
        if !passport.dateOfBirth.isEmpty { info += "Birth: \(passport.dateOfBirth)\n" }
        if !passport.gender.isEmpty { info += "Gender: \(passport.gender)\n" }
        return info.isEmpty ? "Document scanned" : info
    }
    
    func getDataGroupName(_ groupId: DataGroupId) -> String {
        switch groupId {
        case .COM: return "COM"
        case .DG1: return "DG1 (MRZ)"
        case .DG2: return "DG2 (Photo)"
        case .DG11: return "DG11 (Details)"
        case .DG12: return "DG12 (Document)"
        case .DG15: return "DG15 (Auth)"
        case .SOD: return "SOD (Cert)"
        default: return "\(groupId)"
        }
    }
    
    func saveCertificateData(_ sodData: Data, dsc: CertificateInfo, csca: CSCAInfo) {
        let fileManager = FileManager.default
        
        guard let documentsPath = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            print("[ERROR] Failed to get documents directory")
            return
        }
        
        var isDirectory: ObjCBool = false
        if !fileManager.fileExists(atPath: documentsPath.path, isDirectory: &isDirectory) || !isDirectory.boolValue {
            print("[ERROR] Documents directory does not exist or is not a directory")
            return
        }
        
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyyMMdd_HHmmss"
        let timestamp = dateFormatter.string(from: Date())
        
        let docType = MRZHandler.detectDocumentType(documentNumber: documentNumber)
        
        let sodFile = documentsPath.appendingPathComponent("\(docType)_sod_\(timestamp).der")
        let certFile = documentsPath.appendingPathComponent("\(docType)_certificate_\(timestamp).txt")
        let jsonFile = documentsPath.appendingPathComponent("\(docType)_csca_\(timestamp).json")
        
        savedFiles = []
        var successfulWrites: [URL] = []
        
        do {
            try sodData.write(to: sodFile, options: .atomic)
            if fileManager.fileExists(atPath: sodFile.path) {
                print("[SUCCESS] SOD saved: \(sodFile.lastPathComponent) (\(sodData.count) bytes)")
                successfulWrites.append(sodFile)
            } else {
                print("[WARN] SOD write succeeded but file not found: \(sodFile.path)")
            }
            
            let analysis = generateCertificateAnalysis(dsc: dsc, csca: csca)
            try analysis.write(to: certFile, atomically: true, encoding: .utf8)
            if fileManager.fileExists(atPath: certFile.path) {
                print("[SUCCESS] Certificate analysis saved: \(certFile.lastPathComponent)")
                successfulWrites.append(certFile)
            } else {
                print("[WARN] Certificate write succeeded but file not found: \(certFile.path)")
            }
            
            let json = generateCSCAJSON(csca: csca, dsc: dsc)
            try json.write(to: jsonFile, atomically: true, encoding: .utf8)
            if fileManager.fileExists(atPath: jsonFile.path) {
                print("[SUCCESS] JSON saved: \(jsonFile.lastPathComponent)")
                successfulWrites.append(jsonFile)
            } else {
                print("[WARN] JSON write succeeded but file not found: \(jsonFile.path)")
            }
            
            savedFiles = successfulWrites
            
            if successfulWrites.count == 3 {
                print("[SUCCESS] All 3 files saved successfully")
                print("[INFO] Documents path: \(documentsPath.path)")
            } else {
                print("[WARN] Only \(successfulWrites.count)/3 files saved")
            }
            
        } catch let error as NSError {
            print("[ERROR] File save error:")
            print("   Domain: \(error.domain)")
            print("   Code: \(error.code)")
            print("   Description: \(error.localizedDescription)")
            print("   Path: \(documentsPath.path)")
            
            if let underlyingError = error.userInfo[NSUnderlyingErrorKey] as? NSError {
                print("   Underlying error: \(underlyingError.localizedDescription)")
            }
            
            for file in successfulWrites {
                try? fileManager.removeItem(at: file)
            }
            savedFiles = []
        }
    }
    
    func generateCertificateAnalysis(dsc: CertificateInfo, csca: CSCAInfo) -> String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .medium
        
        let daysRemaining = Calendar.current.dateComponents([.day], from: Date(), to: dsc.validUntil).day ?? 0
        let validityStatus = daysRemaining > 30 ? "[VALID]" : daysRemaining >= 0 ? "[EXPIRING SOON]" : "[EXPIRED]"
        
        return """
        ===============================================================
        CSCA & DSC CERTIFICATE ANALYSIS
        ===============================================================
        
        Generated: \(Date())
        Certificate Status: \(validityStatus) (\(daysRemaining) days remaining)
        
        ┌─────────────────────────────────────────────────────┐
        │  CSCA (Country Signing Certificate Authority)      │
        └─────────────────────────────────────────────────────┘
        
        Country:              \(csca.country) (\(csca.countryCode))
        Organization:         \(csca.organization)
        Organizational Unit:  \(csca.organizationalUnit)
        Common Name:          \(csca.commonName)
        
        Distinguished Name:
        \(csca.fullDistinguishedName)
        
        Authority Key ID:     \(csca.authorityKeyIdentifier ?? "N/A")
        
        ┌─────────────────────────────────────────────────────┐
        │  DSC (Document Signing Certificate)                │
        └─────────────────────────────────────────────────────┘
        
        Serial Number:        \(dsc.serialNumber)
        
        Validity:
          Valid From:         \(dateFormatter.string(from: dsc.validFrom))
          Valid Until:        \(dateFormatter.string(from: dsc.validUntil))
          Days Remaining:     \(daysRemaining)
        
        Cryptography:
          Public Key:         \(dsc.publicKeyAlgorithm) (\(dsc.publicKeySize))
          Signature:          \(dsc.signatureAlgorithm)
        
        Identifiers:
          Subject Key ID:     \(dsc.subjectKeyIdentifier ?? "N/A")
          SHA-256 Fingerprint:\(formatFingerprintForText(certificateFingerprint))
        
        Subject DN:
        \(dsc.fullSubjectDN)
        
        ┌─────────────────────────────────────────────────────┐
        │  CERTIFICATE CHAIN                                  │
        └─────────────────────────────────────────────────────┘
        
        CSCA (\(csca.countryCode))
          ↓ signs with \(dsc.signatureAlgorithm)
        DSC
          ↓ signs document data groups
        SOD (Security Object Document)
        
        ┌─────────────────────────────────────────────────────┐
        │  DOCUMENT INFORMATION                               │
        └─────────────────────────────────────────────────────┘
        
        Document Expiry:      \(documentExpiryDate.isEmpty ? "N/A" : documentExpiryDate)
        
        ===============================================================
        """
    }
    
    func formatFingerprintForText(_ fp: String) -> String {
        guard !fp.isEmpty else { return "N/A" }
        var formatted = "\n          "
        for (index, char) in fp.enumerated() {
            if index > 0 && index % 2 == 0 { formatted += ":" }
            if index > 0 && index % 32 == 0 { formatted += "\n          " }
            formatted.append(char)
        }
        return formatted
    }
    
    func generateCSCAJSON(csca: CSCAInfo, dsc: CertificateInfo) -> String {
        let dateFormatter = ISO8601DateFormatter()
        let daysRemaining = Calendar.current.dateComponents([.day], from: Date(), to: dsc.validUntil).day ?? 0
        
        return """
        {
          "scan_timestamp": "\(dateFormatter.string(from: Date()))",
          "document_expiry": "\(documentExpiryDate)",
          "csca": {
            "country": "\(csca.country)",
            "country_code": "\(csca.countryCode)",
            "organization": "\(csca.organization)",
            "organizational_unit": "\(csca.organizationalUnit)",
            "common_name": "\(csca.commonName)",
            "distinguished_name": "\(csca.fullDistinguishedName)",
            "authority_key_identifier": "\(csca.authorityKeyIdentifier ?? "")"
          },
          "dsc": {
            "serial_number": "\(dsc.serialNumber)",
            "subject_dn": "\(dsc.fullSubjectDN)",
            "issuer_dn": "\(dsc.fullIssuerDN)",
            "valid_from": "\(dateFormatter.string(from: dsc.validFrom))",
            "valid_until": "\(dateFormatter.string(from: dsc.validUntil))",
            "days_remaining": \(daysRemaining),
            "is_valid": \(daysRemaining >= 0),
            "public_key_algorithm": "\(dsc.publicKeyAlgorithm)",
            "public_key_size": "\(dsc.publicKeySize)",
            "signature_algorithm": "\(dsc.signatureAlgorithm)",
            "subject_key_identifier": "\(dsc.subjectKeyIdentifier ?? "")",
            "sha256_fingerprint": "\(certificateFingerprint)"
          }
        }
        """
    }
}

// MARK: - UI Components

struct InstructionsCard: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("MRZ Information", systemImage: "doc.text.magnifyingglass")
                .font(.headline)
            
            Text("Look at your document's Machine Readable Zone (MRZ):")
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Image(systemName: "1.circle.fill")
                        .foregroundColor(.blue)
                    Text("Document Number: 7-9 characters")
                }
                HStack {
                    Image(systemName: "2.circle.fill")
                        .foregroundColor(.blue)
                    Text("Birth Date: YYMMDD format")
                }
                HStack {
                    Image(systemName: "3.circle.fill")
                        .foregroundColor(.blue)
                    Text("Expiry Date: YYMMDD format")
                }
            }
            .font(.caption)
        }
        .padding()
        .background(Color.blue.opacity(0.08))
        .cornerRadius(12)
        .padding(.horizontal)
    }
}

struct SmartInputField: View {
    let icon: String
    let title: String
    @Binding var text: String
    let placeholder: String
    var keyboardType: UIKeyboardType = .default
    let isValid: Bool
    let counter: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon)
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            TextField(placeholder, text: $text)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(keyboardType == .numberPad ? .never : .characters)
                .autocorrectionDisabled()
                .keyboardType(keyboardType)
                .onChange(of: text) {
                    if keyboardType == .numberPad {
                        text = String(text.filter { $0.isNumber }.prefix(6))
                    } else {
                        text = String(text.prefix(9).uppercased())
                    }
                }
            
            HStack {
                Text(counter)
                    .font(.caption2)
                    .foregroundColor(isValid ? .green : .secondary)
                
                if !text.isEmpty {
                    Spacer()
                    Image(systemName: isValid ? "checkmark.circle.fill" : "circle")
                        .foregroundColor(isValid ? .green : .gray.opacity(0.3))
                        .font(.caption)
                }
            }
        }
    }
}

struct ValidationBadge: View {
    let isValid: Bool
    
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: isValid ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
            Text(isValid ? "Ready to scan" : "Check your input")
                .font(.subheadline)
                .fontWeight(.medium)
        }
        .foregroundColor(isValid ? .green : .orange)
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(
            (isValid ? Color.green : Color.orange)
                .opacity(0.1)
        )
        .cornerRadius(20)
    }
}

struct ScanButton: View {
    let isScanning: Bool
    let isEnabled: Bool
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                if isScanning {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                } else {
                    Image(systemName: "wave.3.right.circle.fill")
                        .font(.title3)
                }
                
                Text(isScanning ? "Scanning..." : "Start NFC Scan")
                    .fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(isEnabled ? Color.blue : Color.gray)
            .foregroundColor(.white)
            .cornerRadius(12)
        }
        .disabled(!isEnabled || isScanning)
        .padding(.horizontal)
    }
}

struct StatusCard: View {
    let message: String
    let isScanning: Bool
    
    var body: some View {
        Text(message)
            .font(.subheadline)
            .multilineTextAlignment(.center)
            .padding()
            .frame(maxWidth: .infinity)
            .background(
                isScanning ? Color.blue.opacity(0.1) : Color.gray.opacity(0.1)
            )
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(isScanning ? Color.blue.opacity(0.3) : Color.clear, lineWidth: 1)
            )
            .padding(.horizontal)
    }
}

struct CSCAResultView: View {
    let csca: CSCAInfo
    let dsc: CertificateInfo
    let fingerprint: String
    let docExpiry: String
    
    @State private var showFullIssuerDN = false
    @State private var showFullSubjectDN = false
    
    var body: some View {
        VStack(spacing: 16) {
            VStack(spacing: 16) {
                HStack(spacing: 16) {
                    Text(csca.flag)
                        .font(.system(size: 64))
                    
                    VStack(alignment: .leading, spacing: 6) {
                        Text(csca.country)
                            .font(.title)
                            .fontWeight(.bold)
                        
                        Text(csca.countryCode)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                        
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.seal.fill")
                            Text("CSCA Extracted")
                        }
                        .font(.caption)
                        .foregroundColor(.green)
                    }
                    
                    Spacer()
                }
                
                Divider()
                
                VStack(alignment: .leading, spacing: 10) {
                    InfoRow(icon: "building.2.fill", label: "Organization", value: csca.organization)
                    
                    if !csca.organizationalUnit.isEmpty {
                        InfoRow(icon: "person.3.fill", label: "Unit", value: csca.organizationalUnit)
                    }
                    
                    if !csca.commonName.isEmpty {
                        InfoRow(icon: "signature", label: "Common Name", value: csca.commonName)
                    }
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Button(action: { showFullIssuerDN.toggle() }) {
                            HStack {
                                Image(systemName: "info.circle")
                                    .foregroundColor(.blue)
                                Text("Full Distinguished Name")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Spacer()
                                Image(systemName: showFullIssuerDN ? "chevron.up" : "chevron.down")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                        }
                        
                        if showFullIssuerDN {
                            Text(csca.fullDistinguishedName)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.primary)
                                .padding(8)
                                .background(Color.gray.opacity(0.1))
                                .cornerRadius(6)
                        }
                    }
                    
                    if let aki = csca.authorityKeyIdentifier {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Authority Key ID")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(formatKeyID(aki))
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.blue)
                        }
                    }
                }
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(Color.green.opacity(0.08))
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(Color.green.opacity(0.3), lineWidth: 2)
                    )
            )
            
            EnhancedDSCCard(
                dsc: dsc,
                fingerprint: fingerprint,
                docExpiry: docExpiry,
                showFullSubjectDN: $showFullSubjectDN
            )
        }
        .padding(.horizontal)
    }
    
    func formatKeyID(_ id: String) -> String {
        var formatted = ""
        for (index, char) in id.enumerated() {
            if index > 0 && index % 2 == 0 { formatted += ":" }
            formatted.append(char)
        }
        return formatted
    }
}

struct InfoRow: View {
    let icon: String
    let label: String
    let value: String
    
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .foregroundColor(.blue)
                .frame(width: 20)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(value)
                    .font(.subheadline)
            }
        }
    }
}

struct EnhancedDSCCard: View {
    let dsc: CertificateInfo
    let fingerprint: String
    let docExpiry: String
    @Binding var showFullSubjectDN: Bool
    
    var validityStatus: (String, Color, String) {
        let now = Date()
        let daysRemaining = Calendar.current.dateComponents([.day], from: now, to: dsc.validUntil).day ?? 0
        
        if now > dsc.validUntil {
            return ("EXPIRED", .red, "exclamationmark.triangle.fill")
        } else if daysRemaining < 30 {
            return ("EXPIRING SOON", .orange, "exclamationmark.circle.fill")
        } else if daysRemaining < 90 {
            return ("VALID", .yellow, "checkmark.circle.fill")
        } else {
            return ("VALID", .green, "checkmark.seal.fill")
        }
    }
    
    var body: some View {
        VStack(spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Label("DSC Certificate", systemImage: "doc.text.fill")
                        .font(.headline)
                    
                    HStack(spacing: 6) {
                        Image(systemName: validityStatus.2)
                            .foregroundColor(validityStatus.1)
                        Text(validityStatus.0)
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundColor(validityStatus.1)
                    }
                }
                Spacer()
            }
            
            VStack(spacing: 12) {
                Group {
                    DetailSection(title: "IDENTIFICATION", icon: "number.circle.fill") {
                        DetailItem(label: "Serial Number", value: formatSerial(dsc.serialNumber))
                        
                        if !fingerprint.isEmpty {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("SHA-256 Fingerprint")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text(formatFingerprint(fingerprint))
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundColor(.purple)
                            }
                        }
                    }
                }
                
                Divider()
                
                Group {
                    DetailSection(title: "CRYPTOGRAPHY", icon: "lock.shield.fill") {
                        DetailItem(label: "Signature Algorithm", value: dsc.signatureAlgorithm)
                        DetailItem(label: "Public Key Algorithm", value: dsc.publicKeyAlgorithm)
                        DetailItem(label: "Public Key Size", value: dsc.publicKeySize)
                        
                        if let ski = dsc.subjectKeyIdentifier {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Subject Key Identifier")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text(formatKeyID(ski))
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundColor(.green)
                            }
                        }
                    }
                }
                
                Divider()
                
                Group {
                    DetailSection(title: "VALIDITY PERIOD", icon: "calendar.circle.fill") {
                        DetailItem(label: "Valid From", value: formatDate(dsc.validFrom))
                        DetailItem(label: "Valid Until", value: formatDate(dsc.validUntil))
                        
                        let daysRemaining = Calendar.current.dateComponents([.day], from: Date(), to: dsc.validUntil).day ?? 0
                        let totalDays = Calendar.current.dateComponents([.day], from: dsc.validFrom, to: dsc.validUntil).day ?? 1
                        let progress = max(0, min(1, 1 - (Double(daysRemaining) / Double(totalDays))))
                        
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text("Certificate Lifetime")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Spacer()
                                Text("\(daysRemaining) days remaining")
                                    .font(.caption)
                                    .fontWeight(.medium)
                                    .foregroundColor(validityStatus.1)
                            }
                            
                            GeometryReader { geometry in
                                ZStack(alignment: .leading) {
                                    Rectangle()
                                        .fill(Color.gray.opacity(0.2))
                                        .frame(height: 6)
                                        .cornerRadius(3)
                                    
                                    Rectangle()
                                        .fill(validityStatus.1)
                                        .frame(width: geometry.size.width * progress, height: 6)
                                        .cornerRadius(3)
                                }
                            }
                            .frame(height: 6)
                        }
                        
                        if !docExpiry.isEmpty {
                            DetailItem(label: "Document Expires", value: docExpiry)
                        }
                    }
                }
                
                Divider()
                
                Group {
                    DetailSection(title: "SUBJECT", icon: "person.crop.circle.fill") {
                        Button(action: { showFullSubjectDN.toggle() }) {
                            HStack {
                                Image(systemName: "info.circle")
                                    .foregroundColor(.blue)
                                Text("Full Subject Distinguished Name")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Spacer()
                                Image(systemName: showFullSubjectDN ? "chevron.up" : "chevron.down")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                        }
                        
                        if showFullSubjectDN {
                            Text(dsc.fullSubjectDN)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.primary)
                                .padding(8)
                                .background(Color.gray.opacity(0.1))
                                .cornerRadius(6)
                        }
                    }
                }
            }
        }
        .padding()
        .background(Color.purple.opacity(0.06))
        .cornerRadius(12)
        .padding(.horizontal)
    }
    
    func formatSerial(_ serial: String) -> String {
        serial.enumerated().reduce(into: "") { result, element in
            if element.offset > 0 && element.offset % 4 == 0 { result += " " }
            result.append(element.element)
        }
    }
    
    func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter.string(from: date)
    }
    
    func formatFingerprint(_ fp: String) -> String {
        var formatted = ""
        for (index, char) in fp.enumerated() {
            if index > 0 && index % 2 == 0 { formatted += ":" }
            if index > 0 && index % 32 == 0 { formatted += "\n" }
            formatted.append(char)
        }
        return formatted
    }
    
    func formatKeyID(_ id: String) -> String {
        var formatted = ""
        for (index, char) in id.enumerated() {
            if index > 0 && index % 2 == 0 { formatted += ":" }
            formatted.append(char)
        }
        return formatted
    }
}

struct DetailSection<Content: View>: View {
    let title: String
    let icon: String
    let content: Content
    
    init(title: String, icon: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.icon = icon
        self.content = content()
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon)
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(.blue)
            
            content
        }
    }
}

struct DetailItem: View {
    let label: String
    let value: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(value)
                .font(.subheadline)
        }
    }
}

struct DocumentInfoCard: View {
    let info: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Document Information", systemImage: "person.text.rectangle")
                .font(.headline)
                .foregroundColor(.blue)
            
            Text(info)
                .font(.system(.caption, design: .monospaced))
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.blue.opacity(0.06))
                .cornerRadius(8)
        }
        .padding(.horizontal)
    }
}

struct DataGroupsCard: View {
    let groups: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Data Groups Read", systemImage: "list.bullet.rectangle")
                .font(.headline)
                .foregroundColor(.green)
            
            Text(groups)
                .font(.system(.caption, design: .monospaced))
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.green.opacity(0.06))
                .cornerRadius(8)
        }
        .padding(.horizontal)
    }
}

struct ExportButton: View {
    let fileCount: Int
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: "square.and.arrow.up.circle.fill")
                Text("Export Certificate Data (\(fileCount) files)")
                    .fontWeight(.medium)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color.green.opacity(0.1))
            .foregroundColor(.green)
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(Color.green, lineWidth: 1.5)
            )
        }
        .padding(.horizontal)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
