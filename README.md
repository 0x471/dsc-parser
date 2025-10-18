# DSC Parser
An iOS app for reading NFC-enabled passports and ID cards to extract and analyze the Document Signing Certificate (DSC) and Country Signing Certificate Authority (CSCA) information.

## What this does
This app reads the NFC chip in electronic passports and ID cards, extracts the certificate data, and gives you detailed information about the signing authorities. It's useful for understanding the certificate chain used to secure biometric documents, or if you just want to see what data is actually stored in your passport's chip.The main point here is extracting the CSCA information from the DSC certificate embedded in the Security Object Document (SOD). Most apps just read the basic biographical data - this one focuses on the cryptographic certificates instead.

## How to use it
You need three pieces of information from your document's Machine Readable Zone (MRZ):
1. **Document Number** - Usually 7-9 characters, found on the ID line
2. **Date of Birth** - In YYMMDD format (e.g., 900315 for March 15, 1990)
3. **Expiry Date** - Also YYMMDD format

The app will try multiple MRZ key variations automatically since different countries format their document numbers differently. Some pad with `<` characters, some don't. The app handles this.

Hold your phone against the passport's NFC chip (usually on the photo page) and wait. The scan takes 5-10 seconds typically.


## What you get
The app extracts and displays:
- **CSCA Details**: Country, organization, distinguished name, authority key identifier
- **DSC Details**: Serial number, validity period, signature algorithm, public key info
- **Certificate Chain**: Visual representation of CSCA → DSC → SOD
- **Cryptographic Info**: Algorithms used (RSA/ECDSA), key sizes, fingerprints
- **Data Groups**: Which data groups were successfully read from the chip


## Requirements
- iOS device with NFC capability (iPhone 7 or later)
- Swift 5.5+
- Xcode 14.0+
- NFCPassportReader Swift package

Your app needs the NFC capability enabled in Xcode and the appropriate entries in Info.plist.