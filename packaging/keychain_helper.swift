import Foundation
import Security
import LocalAuthentication

private let keychainService = "HopHarbor"
private let maximumInputBytes = 65_536

private enum HelperFailure: Error {
    case invalidRequest
    case invalidID
    case invalidSecret
    case keychain(OSStatus)
    case unknownPrompt
    case missingSecret
}

private func emit(_ value: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
}

private func validID(_ identifier: String) -> Bool {
    identifier.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil
}

private func request() throws -> [String: Any] {
    var buffer = Data()
    while true {
        let chunk = FileHandle.standardInput.readData(ofLength: 4096)
        if chunk.isEmpty { break }
        buffer.append(chunk)
        if buffer.count > maximumInputBytes { throw HelperFailure.invalidRequest }
    }
    guard !buffer.isEmpty,
          let object = try? JSONSerialization.jsonObject(with: buffer),
          let body = object as? [String: Any] else { throw HelperFailure.invalidRequest }
    return body
}

private func identifier(from body: [String: Any]) throws -> String {
    guard let identifier = body["server_id"] as? String, validID(identifier) else { throw HelperFailure.invalidID }
    return identifier
}

private func query(_ kind: String, _ identifier: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: kind + ":" + identifier,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
}

private func has(_ kind: String, _ identifier: String) throws -> Bool {
    var search = query(kind, identifier)
    search[kSecReturnAttributes as String] = true
    let context = LAContext()
    context.interactionNotAllowed = true
    search[kSecUseAuthenticationContext as String] = context
    let status = SecItemCopyMatching(search as CFDictionary, nil)
    if status == errSecItemNotFound { return false }
    guard status == errSecSuccess else { throw HelperFailure.keychain(status) }
    return true
}

private func secretValue(_ body: [String: Any], key: String) throws -> String? {
    guard let candidate = body[key], !(candidate is NSNull) else { return nil }
    guard let value = candidate as? String,
          !value.isEmpty,
          value.utf8.count <= 8192,
          value.rangeOfCharacter(from: CharacterSet(charactersIn: "\0\r\n")) == nil else {
        throw HelperFailure.invalidSecret
    }
    return value
}

private func put(_ kind: String, _ identifier: String, _ secret: String) throws {
    var matching = query(kind, identifier)
    matching.removeValue(forKey: kSecMatchLimit as String)
    let update = [kSecValueData as String: Data(secret.utf8)]
    let updated = SecItemUpdate(matching as CFDictionary, update as CFDictionary)
    if updated == errSecSuccess { return }
    guard updated == errSecItemNotFound else { throw HelperFailure.keychain(updated) }
    matching[kSecValueData as String] = Data(secret.utf8)
    matching[kSecAttrLabel as String] = "HopHarbor · " + identifier
    matching[kSecAttrDescription as String] = kind == "password" ? "SSH server password" : "SSH private key passphrase"
    let added = SecItemAdd(matching as CFDictionary, nil)
    guard added == errSecSuccess else { throw HelperFailure.keychain(added) }
}

private func delete(_ kind: String, _ identifier: String) throws {
    var matching = query(kind, identifier)
    matching.removeValue(forKey: kSecMatchLimit as String)
    let status = SecItemDelete(matching as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else { throw HelperFailure.keychain(status) }
}

private func readSecret(_ kind: String, _ identifier: String) throws -> Data {
    var search = query(kind, identifier)
    search[kSecReturnData as String] = true
    // An unattended SSH child must not block on an unexpected Keychain dialog.
    let context = LAContext()
    context.interactionNotAllowed = true
    search[kSecUseAuthenticationContext as String] = context
    var item: CFTypeRef?
    let status = SecItemCopyMatching(search as CFDictionary, &item)
    if status == errSecItemNotFound { throw HelperFailure.missingSecret }
    guard status == errSecSuccess, let data = item as? Data,
          !data.isEmpty, data.count <= 8192,
          !data.contains(0), !data.contains(10), !data.contains(13) else {
        throw HelperFailure.keychain(status)
    }
    return data
}

private func status(_ identifier: String) throws -> [String: Any] {
    ["ok": true,
     "has_password": try has("password", identifier),
     "has_key_passphrase": try has("passphrase", identifier)]
}

private func askpass() throws {
    guard let identifier = ProcessInfo.processInfo.environment["PM_SERVER_ID"], validID(identifier) else {
        throw HelperFailure.invalidID
    }
    let prompt = CommandLine.arguments.dropFirst(2).joined(separator: " ").lowercased()
    guard !prompt.isEmpty, prompt.utf8.count <= 16_384,
          !prompt.contains("yes/no"), !prompt.contains("fingerprint"),
          !prompt.contains("continue connecting"), !prompt.contains("host key"),
          !prompt.contains("authenticity of host") else { throw HelperFailure.unknownPrompt }
    let kind: String
    if prompt.contains("passphrase") {
        kind = "passphrase"
    } else if prompt.contains("password") {
        kind = "password"
    } else {
        // Never answer arbitrary keyboard-interactive/OTP or confirmation prompts.
        throw HelperFailure.unknownPrompt
    }
    let data = try readSecret(kind, identifier)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
}

do {
    guard CommandLine.arguments.count >= 2 else { throw HelperFailure.invalidRequest }
    let mode = CommandLine.arguments[1]
    if mode == "askpass" {
        try askpass()
    } else {
        guard CommandLine.arguments.count == 2 else { throw HelperFailure.invalidRequest }
        let body = try request()
        let identifier = try identifier(from: body)
        switch mode {
        case "has":
            emit(try status(identifier))
        case "put":
            let password = try secretValue(body, key: "password")
            let passphrase = try secretValue(body, key: "key_passphrase")
            guard password != nil || passphrase != nil else { throw HelperFailure.invalidRequest }
            if let value = password { try put("password", identifier, value) }
            if let value = passphrase { try put("passphrase", identifier, value) }
            emit(try status(identifier))
        case "delete":
            try delete("password", identifier)
            try delete("passphrase", identifier)
            emit(["ok": true, "has_password": false, "has_key_passphrase": false])
        default:
            throw HelperFailure.invalidRequest
        }
    }
} catch {
    // Askpass stdout belongs exclusively to SSH. In error cases it is empty.
    if CommandLine.arguments.dropFirst().first != "askpass" {
        if case HelperFailure.keychain(let code) = error {
            emit(["ok": false, "error": "keychain_unavailable", "status": Int(code)])
        } else {
            emit(["ok": false, "error": "invalid_request"])
        }
    }
    exit(1)
}
