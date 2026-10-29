using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace HopHarbor.NativeHelper;

internal static class Program
{
    private const int MaximumRequestBytes = 65536;
    // OpenSSH askpass reads a 1024-byte buffer, including our final newline and
    // its terminator. Stay below that boundary instead of silently truncating.
    private const int MaximumSecretBytes = 1022;
    private static readonly Regex Identifier = new("^[A-Za-z0-9_-]{1,64}$", RegexOptions.CultureInvariant);
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly HashSet<string> Modes = ["has", "put", "delete", "askpass", "hop", "control", "prepare", "prepare-package"];

    [STAThread]
    private static int Main(string[] args)
    {
        var askpass = args.Length == 1 && !Modes.Contains(args[0]);
        askpass |= args.Length > 0 && args[0] == "askpass";
        try
        {
            if (!OperatingSystem.IsWindows() || args.Length == 0) throw new InvalidDataException();
            if (askpass)
            {
                var prompt = args[0] == "askpass" ? string.Join(' ', args.Skip(1)) : args[0];
                Askpass(prompt);
                return 0;
            }
            if (args[0] == "hop") return Hop(args.Skip(1).ToArray());
            if (args[0] == "prepare-package")
            {
                var options = Options(args.Skip(1).ToArray(), ["app-dir"]);
                WindowsFiles.PreparePackage(options["app-dir"]);
                Emit(new { ok = true });
                return 0;
            }
            if (args[0] is "prepare" or "control")
            {
                var options = Options(args.Skip(1).ToArray(), ["data-dir"]);
                var directory = WindowsFiles.LocalPath(options["data-dir"]);
                if (args[0] == "prepare")
                {
                    WindowsFiles.PrepareDirectory(directory);
                    Emit(new { ok = true });
                }
                else
                {
                    WindowsFiles.ValidateDirectory(directory);
                    using var stream = WindowsFiles.OpenPrivateRead(Path.Combine(directory, "control.json"));
                    using var control = ReadJson(stream, 16384);
                    var root = control.RootElement;
                    if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("port", out var portValue)
                        || !portValue.TryGetInt32(out var port) || port is < 1024 or > 65535
                        || !root.TryGetProperty("token", out var tokenValue) || tokenValue.ValueKind != JsonValueKind.String)
                        throw new InvalidDataException();
                    var token = tokenValue.GetString()!;
                    if (token.Length is < 20 or > 4096 || token.Any(char.IsControl)) throw new InvalidDataException();
                    Emit(new { ok = true, port, token });
                }
                return 0;
            }
            if (args.Length != 1 || args[0] is not ("has" or "put" or "delete")) throw new InvalidDataException();
            using var request = ReadJson(Console.OpenStandardInput(), MaximumRequestBytes);
            var body = request.RootElement;
            if (body.ValueKind != JsonValueKind.Object || !body.TryGetProperty("server_id", out var idValue)
                || idValue.ValueKind != JsonValueKind.String) throw new InvalidDataException();
            var id = idValue.GetString()!;
            if (!Identifier.IsMatch(id)) throw new InvalidDataException();
            switch (args[0])
            {
                case "has": Emit(Status(id)); break;
                case "put":
                    // Validate all supplied values before mutating either credential.
                    var password = Secret(body, "password");
                    var passphrase = Secret(body, "key_passphrase");
                    if (password is null && passphrase is null) throw new InvalidDataException();
                    try
                    {
                        if (password is not null) Vault.Put("password", id, password);
                        if (passphrase is not null) Vault.Put("passphrase", id, passphrase);
                    }
                    finally
                    {
                        if (password is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(password);
                        if (passphrase is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(passphrase);
                    }
                    Emit(Status(id));
                    break;
                case "delete":
                    Vault.Delete("password", id); Vault.Delete("passphrase", id);
                    Emit(new { ok = true, has_password = false, has_key_passphrase = false });
                    break;
            }
            return 0;
        }
        catch
        {
            // Raw provider exception text, prompts, paths and secrets never enter output.
            // Askpass/hop stdout is exclusively the SSH data stream.
            if (!askpass && (args.Length == 0 || args[0] != "hop"))
                Emit(new { ok = false, error = "windows_credentials_or_private_data_unavailable" });
            return 1;
        }
    }

    private static Dictionary<string, string> Options(string[] args, string[] names)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (args.Length != names.Length * 2) throw new InvalidDataException();
        for (var i = 0; i < args.Length; i += 2)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal)) throw new InvalidDataException();
            var key = args[i][2..];
            if (!names.Contains(key) || !result.TryAdd(key, args[i + 1])) throw new InvalidDataException();
        }
        return result;
    }

    private static JsonDocument ReadJson(Stream stream, int maximum)
    {
        using var memory = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var count = stream.Read(buffer, 0, buffer.Length);
            if (count == 0) break;
            if (memory.Length + count > maximum) throw new InvalidDataException();
            memory.Write(buffer, 0, count);
        }
        if (memory.Length == 0) throw new InvalidDataException();
        return JsonDocument.Parse(memory.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
    }

    private static byte[]? Secret(JsonElement body, string name)
    {
        if (!body.TryGetProperty(name, out var element) || element.ValueKind == JsonValueKind.Null) return null;
        if (element.ValueKind != JsonValueKind.String) throw new InvalidDataException();
        var value = element.GetString()!;
        if (value.Length == 0 || value.IndexOfAny(['\0', '\r', '\n']) >= 0) throw new InvalidDataException();
        var bytes = Utf8.GetBytes(value);
        if (bytes.Length > MaximumSecretBytes)
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException();
        }
        return bytes;
    }

    private static object Status(string id) => new { ok = true, has_password = Vault.Has("password", id), has_key_passphrase = Vault.Has("passphrase", id) };

    private static void Askpass(string prompt)
    {
        var id = Environment.GetEnvironmentVariable("PM_SERVER_ID");
        if (id is null || !Identifier.IsMatch(id) || prompt.Length is 0 or > 16384) throw new InvalidDataException();
        var text = prompt.ToLowerInvariant();
        if (new[] { "yes/no", "fingerprint", "continue connecting", "host key", "authenticity of host", "verification code", "one-time", "otp" }.Any(text.Contains))
            throw new InvalidDataException();
        var kind = text.Contains("passphrase") ? "passphrase" : text.Contains("password") ? "password" : throw new InvalidDataException();
        var bytes = Vault.Read(kind, id);
        try
        {
            if (bytes.Length is 0 or > MaximumSecretBytes || bytes.Any(b => b is 0 or 10 or 13)) throw new InvalidDataException();
            _ = Utf8.GetString(bytes); // Reject a malformed blob rather than returning arbitrary bytes.
            using var output = Console.OpenStandardOutput();
            output.Write(bytes);
            output.WriteByte(10);
            output.Flush();
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    private static int Hop(string[] args)
    {
        var options = Options(args, ["server", "host", "port"]);
        var id = options["server"]; var host = options["host"];
        if (!Identifier.IsMatch(id) || !int.TryParse(options["port"], NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 1 or > 65535 || host.Length is 0 or > 253 || host.Any(c => c < 33 || c > 126)
            || host.IndexOfAny(['%', '\\', '/', '"', '\'']) >= 0 || host.StartsWith('-')
            || !(IPAddress.TryParse(host, out _) || Regex.IsMatch(host, "^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$", RegexOptions.CultureInvariant)))
            throw new InvalidDataException();
        var data = WindowsFiles.LocalPath(Environment.GetEnvironmentVariable("PM_DATA_DIR") ?? "");
        var app = WindowsFiles.LocalPath(Environment.GetEnvironmentVariable("HOPHARBOR_APP") ?? "");
        WindowsFiles.ValidateDirectory(data);
        WindowsFiles.ValidateDirectory(app);
        var config = Path.Combine(data, "ssh_config");
        using (WindowsFiles.OpenPrivateRead(config)) { }
        var helper = Path.Combine(app, "bin", "HopHarborHelper.exe");
        using (WindowsFiles.OpenPrivateRead(helper)) { }
        var ssh = Native.SystemSsh();
        var target = host.Contains(':') ? $"[{host}]:{port}" : $"{host}:{port}";
        var environment = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(entry => (string)entry.Key, entry => (string?)entry.Value ?? "", StringComparer.OrdinalIgnoreCase);
        environment["PM_SERVER_ID"] = id;
        environment["PM_DATA_DIR"] = data;
        environment["HOPHARBOR_APP"] = app;
        environment["SSH_ASKPASS"] = helper;
        environment["SSH_ASKPASS_REQUIRE"] = "force";
        environment["DISPLAY"] = "HopHarbor";
        environment["LC_ALL"] = "C";
        return Native.RunInherited(ssh, ["-F", config, "-W", target, "pm_" + id], environment);
    }

    private static void Emit(object value)
    {
        using var output = Console.OpenStandardOutput();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        output.Write(bytes); output.WriteByte(10); output.Flush();
    }
}

internal static class Vault
{
    private const uint Generic = 1;
    private static string Target(string kind, string id) => $"HopHarbor:{kind}:{id}";

    internal static bool Has(string kind, string id)
    {
        if (!Native.CredReadW(Target(kind, id), Generic, 0, out var pointer))
        {
            if (Marshal.GetLastWin32Error() == 1168) return false;
            throw new Win32Exception();
        }
        Native.CredFree(pointer); // Presence does not copy or decode the blob.
        return true;
    }

    internal static byte[] Read(string kind, string id)
    {
        if (!Native.CredReadW(Target(kind, id), Generic, 0, out var pointer)) throw new Win32Exception();
        try
        {
            var credential = Marshal.PtrToStructure<Native.Credential>(pointer);
            if (credential.BlobSize is 0 or > 2560 || credential.Blob == IntPtr.Zero) throw new InvalidDataException();
            var result = new byte[credential.BlobSize];
            Marshal.Copy(credential.Blob, result, 0, result.Length);
            return result;
        }
        finally { Native.CredFree(pointer); }
    }

    internal static void Put(string kind, string id, byte[] secret)
    {
        var buffer = Marshal.AllocHGlobal(secret.Length);
        try
        {
            Marshal.Copy(secret, 0, buffer, secret.Length);
            var credential = new Native.Credential { Type = Generic, TargetName = Target(kind, id),
                Comment = "HopHarbor SSH authentication", BlobSize = (uint)secret.Length, Blob = buffer,
                Persist = 2, UserName = kind + ":" + id };
            if (!Native.CredWriteW(ref credential, 0)) throw new Win32Exception();
        }
        finally
        {
            for (var i = 0; i < secret.Length; i++) Marshal.WriteByte(buffer, i, 0);
            Marshal.FreeHGlobal(buffer);
        }
    }

    internal static void Delete(string kind, string id)
    {
        if (!Native.CredDeleteW(Target(kind, id), Generic, 0) && Marshal.GetLastWin32Error() != 1168)
            throw new Win32Exception();
    }
}

internal static class WindowsFiles
{
    private static readonly HashSet<string> Privileged = ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];
    private const uint ParentWrite = 0x10000 | 0x40000 | 0x80000 | 0x100 | 0x10 | 0x40 | 0x40000000 | 0x10000000;
    private const uint AnchoredRootMetadata = 0x10000 | 0x100 | 0x10;
    private static SecurityIdentifier User => WindowsIdentity.GetCurrent().User ?? throw new SecurityException();

    internal static string LocalPath(string path)
    {
        if (path.Length == 0 || path.Contains('\0')) throw new InvalidDataException();
        path = path.Replace('/', '\\');
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\') throw new InvalidDataException();
        foreach (var component in path[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            if (component is "." or ".." || component.Contains(':') || component.EndsWith(' ') || component.EndsWith('.')) throw new InvalidDataException();
            var name = component.Split('.')[0].ToUpperInvariant();
            if (name is "CON" or "PRN" or "AUX" or "NUL" || Regex.IsMatch(name, "^(COM|LPT)[1-9]$")) throw new InvalidDataException();
        }
        return Path.GetFullPath(path).TrimEnd('\\');
    }

    private static SafeFileHandle Open(string path, uint access = 0x20080, uint share = 3)
    {
        var handle = Native.CreateFileW("\\\\?\\" + path, access, share, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception();
        return handle;
    }

    private static Native.FileInformation Info(SafeFileHandle handle)
    {
        if (!Native.GetFileInformationByHandle(handle, out var info)) throw new Win32Exception();
        if ((info.Attributes & 0x400) != 0) throw new SecurityException("Reparse point rejected.");
        return info;
    }

    private static void ValidateAcl(SafeFileHandle handle, bool privateObject, bool preparingPackage = false, bool anchoredVolumeRoot = false)
    {
        if (anchoredVolumeRoot && (privateObject || preparingPackage)) throw new SecurityException();
        var rc = Native.GetSecurityInfo(handle, 1, 5, out _, IntPtr.Zero, out _, IntPtr.Zero, out var pointer);
        if (rc != 0) throw new Win32Exception((int)rc);
        try
        {
            var length = checked((int)Native.GetSecurityDescriptorLength(pointer));
            if (length is <= 0 or > 65536) throw new InvalidDataException();
            var bytes = new byte[length]; Marshal.Copy(pointer, bytes, 0, length);
            var descriptor = new RawSecurityDescriptor(bytes, 0);
            var user = User.Value;
            if (descriptor.Owner is null || (privateObject || preparingPackage ? descriptor.Owner.Value != user : descriptor.Owner.Value != user && !Privileged.Contains(descriptor.Owner.Value)))
                throw new SecurityException("Unexpected owner.");
            if (descriptor.DiscretionaryAcl is null) throw new SecurityException("Unrestricted ACL.");
            var userSeen = false;
            foreach (GenericAce generic in descriptor.DiscretionaryAcl)
            {
                if (generic is not CommonAce ace || ace.IsCallback || ace.SecurityIdentifier is null) throw new SecurityException("Unsupported ACL.");
                if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
                if (ace.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied)) throw new SecurityException("Unsupported ACL.");
                if (ace.AceQualifier != AceQualifier.AccessAllowed) continue;
                var sid = ace.SecurityIdentifier.Value;
                if (sid == user) userSeen = true;
                var known = sid == user || Privileged.Contains(sid);
                var mutation = (anchoredVolumeRoot ? ParentWrite & ~AnchoredRootMetadata : ParentWrite) | (preparingPackage ? 0x6u : 0u);
                if (privateObject && !known || !privateObject && !known && ((uint)ace.AccessMask & mutation) != 0)
                    throw new SecurityException("Non-private ACL.");
            }
            if (privateObject && !userSeen) throw new SecurityException("No user access.");
        }
        finally { Native.LocalFree(pointer); }
    }

    private static List<SafeFileHandle> Parents(string path)
    {
        var handles = new List<SafeFileHandle>();
        try
        {
            var parent = Path.GetPathRoot(path)!;
            var root = parent;
            SecurityException? rootFailure = null;
            var components = path[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
            for (var i = -1; i < components.Length - 1; i++)
            {
                if (i >= 0) parent = Path.Combine(parent, components[i]);
                var handle = Open(parent); handles.Add(handle);
                if ((Info(handle).Attributes & 0x10) == 0) throw new SecurityException();
                if (i == -1)
                {
                    try { ValidateAcl(handle, false); }
                    catch (SecurityException error) { rootFailure = error; }
                }
                else
                {
                    ValidateAcl(handle, false);
                    if (i == 0 && rootFailure is not null)
                    {
                        VerifyRootAnchor(handles[0], root, handle, components[0]);
                        ValidateAcl(handles[0], false, anchoredVolumeRoot: true);
                        rootFailure = null;
                    }
                }
            }
            if (rootFailure is not null) throw new SecurityException("A protected first child is required for this volume root.", rootFailure);
            return handles;
        }
        catch { foreach (var handle in handles) handle.Dispose(); throw; }
    }

    private static string FinalVolumePath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(32768);
        var count = Native.GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 1);
        if (count == 0 || count >= buffer.Capacity) throw new Win32Exception();
        return buffer.ToString();
    }

    private static void VerifyRootAnchor(SafeFileHandle root, string rootPath, SafeFileHandle child, string component)
    {
        if (rootPath.Length != 3 || rootPath[1] != ':' || rootPath[2] != '\\'
            || component.Length == 0 || Path.GetFileName(component) != component || Native.GetDriveTypeW(rootPath) != 3)
            throw new SecurityException();
        var buffer = new StringBuilder(64);
        if (!Native.GetVolumeNameForVolumeMountPointW(rootPath, buffer, (uint)buffer.Capacity)) throw new Win32Exception();
        var volume = buffer.ToString();
        const string prefix = "\\\\?\\Volume{";
        if (!volume.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !volume.EndsWith("}\\", StringComparison.Ordinal)
            || !Guid.TryParseExact(volume[prefix.Length..^2], "D", out _)) throw new SecurityException();
        if (!string.Equals(FinalVolumePath(root), volume, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(FinalVolumePath(child), volume + component, StringComparison.OrdinalIgnoreCase)) throw new SecurityException();
        // MS-FSA FSCTL_SET_REPARSE_POINT rejects every nonempty directory.
        // The held, strictly protected direct child anchors nonemptiness. Check
        // the root again after child identity to close a reparse/restore race.
        if ((Info(root).Attributes & 0x10) == 0) throw new SecurityException();
    }

    internal static void ValidateDirectory(string path)
    {
        path = LocalPath(path); var parents = Parents(path);
        try
        {
            using var handle = Open(path);
            if ((Info(handle).Attributes & 0x10) == 0) throw new SecurityException();
            ValidateAcl(handle, true);
        }
        finally { foreach (var handle in parents) handle.Dispose(); }
    }

    internal static void PrepareDirectory(string path)
    {
        path = LocalPath(path);
        var parent = Path.GetDirectoryName(path);
        if (parent is null || path.Length <= 3) throw new SecurityException();
        if (!Directory.Exists(parent)) PrepareDirectory(parent);
        var parents = Parents(path);
        try
        {
            var user = User;
            var security = new DirectorySecurity();
            security.SetOwner(user); security.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { user, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            if (!Directory.Exists(path)) FileSystemAclExtensions.CreateDirectory(security, path);
            using var handle = Open(path);
            if ((Info(handle).Attributes & 0x10) == 0) throw new SecurityException();
            // Validate owner before applying a restrictive ACL; never take ownership.
            var original = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner);
            if (original.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier originalOwner || originalOwner.Value != user.Value) throw new SecurityException();
            try { ValidateAcl(handle, true); return; }
            catch (SecurityException) { }
            // Do not propagate unchanged ACLs through a potentially large
            // WebView cache every time the panel is reopened.
            new DirectoryInfo(path).SetAccessControl(security);
            ValidateAcl(handle, true);
        }
        finally { foreach (var handle in parents) handle.Dispose(); }
    }

    internal static void PreparePackage(string path)
    {
        // The first launch cannot import unprotected Python code to protect
        // itself. Limit this bootstrap to our recognized, per-user install.
        path = LocalPath(path);
        var expected = LocalPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "HopHarbor"));
        if (!string.Equals(path, expected, StringComparison.OrdinalIgnoreCase)) throw new SecurityException();
        var parents = Parents(path);
        var entries = new List<(string Path, bool Directory, SafeFileHandle Handle)>();
        try
        {
            void Inspect(string entry)
            {
                if (entries.Count >= 20000) throw new InvalidDataException();
                var handle = Open(entry, 0x60080); // READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES.
                entries.Add((entry, false, handle));
                var info = Info(handle);
                var directory = (info.Attributes & 0x10) != 0;
                if (!directory && info.Links != 1) throw new SecurityException();
                ValidateAcl(handle, false, preparingPackage: true);
                entries[^1] = (entry, directory, handle);
                if (directory)
                    foreach (var child in Directory.EnumerateFileSystemEntries(entry)) Inspect(LocalPath(child));
            }
            Inspect(path);
            var required = new[] { "runtime/python.exe", "runtime/pythonw.exe", "bin/HopHarborHelper.exe", "windows_proxy.py", "ui/HopHarbor.exe", "hopharbor-package.json" };
            foreach (var relative in required)
            {
                var full = Path.Combine(path, relative.Replace('/', '\\'));
                if (!entries.Any(entry => !entry.Directory && string.Equals(entry.Path, full, StringComparison.OrdinalIgnoreCase)))
                    throw new InvalidDataException();
            }
            var markerPath = Path.Combine(path, "hopharbor-package.json");
            using (var markerHandle = Open(markerPath, 0x80020080))
            using (var marker = new FileStream(markerHandle, FileAccess.Read))
            {
                if (marker.Length is <= 0 or > 4096) throw new InvalidDataException();
                using var document = JsonDocument.Parse(marker, new JsonDocumentOptions { MaxDepth = 4 });
                var root = document.RootElement;
                if (root.GetProperty("name").GetString() != "HopHarbor"
                    || root.GetProperty("architecture").GetString() is not ("arm64" or "x64")
                    || !Version.TryParse(root.GetProperty("version").GetString(), out _)
                    || !root.GetProperty("build").TryGetInt32(out var build) || build < 1) throw new InvalidDataException();
            }
            // Complete the preflight before changing any ACL. Held no-delete
            // handles prevent a parent, file or directory being swapped out.
            foreach (var entry in entries)
            {
                var inheritance = entry.Directory ? "OICI" : "";
                var sddl = $"D:P(A;{inheritance};FA;;;{User.Value})(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)";
                if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out var descriptor, out _)) throw new Win32Exception();
                try
                {
                    if (!Native.GetSecurityDescriptorDacl(descriptor, out var present, out var dacl, out _) || !present || dacl == IntPtr.Zero)
                        throw new SecurityException();
                    var rc = Native.SetSecurityInfo(entry.Handle, 1, 0x80000004, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                    if (rc != 0) throw new Win32Exception((int)rc);
                    ValidateAcl(entry.Handle, true);
                }
                finally { Native.LocalFree(descriptor); }
            }
        }
        finally
        {
            foreach (var entry in entries) entry.Handle.Dispose();
            foreach (var handle in parents) handle.Dispose();
        }
    }

    internal static FileStream OpenPrivateRead(string path)
    {
        path = LocalPath(path); var parents = Parents(path);
        try
        {
            var handle = Open(path, 0x80020080, 1);
            try
            {
                var info = Info(handle);
                if ((info.Attributes & 0x10) != 0 || info.Links != 1) throw new SecurityException();
                ValidateAcl(handle, true);
                return new FileStream(handle, FileAccess.Read);
            }
            catch { handle.Dispose(); throw; }
        }
        finally { foreach (var handle in parents) handle.Dispose(); }
    }
}

internal static class Native
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct Credential
    {
        internal uint Flags, Type;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? Comment;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        internal uint BlobSize; internal IntPtr Blob; internal uint Persist, AttributeCount;
        internal IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] internal string? UserName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileInformation
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        internal int Size;
        internal IntPtr Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        internal ushort Show, ReservedSize;
        internal IntPtr ReservedBytes, Input, Output, Error;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        internal StartupInfo Info;
        internal IntPtr Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal IntPtr Process, Thread;
        internal uint ProcessId, ThreadId;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CredReadW(string target, uint type, uint flags, out IntPtr credential);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CredWriteW(ref Credential credential, uint flags);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CredDeleteW(string target, uint type, uint flags);
    [DllImport("advapi32.dll")] internal static extern void CredFree(IntPtr credential);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint information, out IntPtr owner, IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] internal static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, [MarshalAs(UnmanagedType.Bool)] out bool present, out IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint SetSecurityInfo(SafeFileHandle handle, uint type, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern uint GetWindowsDirectoryW(StringBuilder directory, uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] internal static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetVolumeNameForVolumeMountPointW(string root, StringBuilder volume, uint length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder name, uint length, uint flags);
    [DllImport("kernel32.dll")] private static extern IntPtr GetStdHandle(int which);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInformation process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref nuint bytes);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, nuint attribute, IntPtr value, nuint bytes, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr handle, out uint code);

    internal static string SystemSsh()
    {
        var buffer = new StringBuilder(32768); var length = GetWindowsDirectoryW(buffer, (uint)buffer.Capacity);
        if (length == 0 || length >= buffer.Capacity) throw new Win32Exception();
        var path = Path.Combine(buffer.ToString(), "System32", "OpenSSH", "ssh.exe");
        if (!File.Exists(path)) throw new FileNotFoundException();
        return path;
    }

    private static string Quote(string argument)
    {
        if (argument.Contains('\0')) throw new InvalidDataException();
        if (argument.Length > 0 && !argument.Any(c => char.IsWhiteSpace(c) || c == '"')) return argument;
        var result = new StringBuilder("\""); var slashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\') { slashes++; continue; }
            if (character == '"') { result.Append('\\', slashes * 2 + 1); result.Append('"'); slashes = 0; continue; }
            result.Append('\\', slashes); slashes = 0; result.Append(character);
        }
        result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
    }

    internal static int RunInherited(string executable, string[] arguments, Dictionary<string, string> environment)
    {
        // The helper remains inside the controller's Job Object. Child SSH hops
        // inherit that job, so no recursive hop can survive controller cleanup.
        var block = string.Join('\0', environment.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
        var environmentPointer = Marshal.StringToHGlobalUni(block);
        IntPtr attributes = IntPtr.Zero, handleArray = IntPtr.Zero;
        var initialized = false;
        try
        {
            var handles = new[] { GetStdHandle(-10), GetStdHandle(-11), GetStdHandle(-12) };
            if (handles.Any(handle => handle == IntPtr.Zero || handle == new IntPtr(-1))) throw new InvalidDataException();
            var allowed = handles.Distinct().ToArray();
            foreach (var handle in allowed)
                if (!SetHandleInformation(handle, 1, 1)) throw new Win32Exception();
            nuint size = 0;
            _ = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size is 0 or > 65536) throw new InvalidDataException();
            attributes = Marshal.AllocHGlobal(checked((int)size));
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new Win32Exception();
            initialized = true;
            handleArray = Marshal.AllocHGlobal(IntPtr.Size * allowed.Length);
            Marshal.Copy(allowed, 0, handleArray, allowed.Length);
            if (!UpdateProcThreadAttribute(attributes, 0, 0x00020002, handleArray,
                (nuint)(IntPtr.Size * allowed.Length), IntPtr.Zero, IntPtr.Zero)) throw new Win32Exception();
            var startup = new StartupInfoEx { Info = new StartupInfo { Size = Marshal.SizeOf<StartupInfoEx>(), Flags = 0x100,
                Input = handles[0], Output = handles[1], Error = handles[2] }, Attributes = attributes };
            var command = new StringBuilder(string.Join(' ', new[] { executable }.Concat(arguments).Select(Quote)));
            if (!CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true, 0x08080400,
                environmentPointer, Path.GetDirectoryName(executable)!, ref startup, out var process)) throw new Win32Exception();
            try
            {
                if (WaitForSingleObject(process.Process, 0xFFFFFFFF) != 0 || !GetExitCodeProcess(process.Process, out var code)) throw new Win32Exception();
                return unchecked((int)code);
            }
            finally { CloseHandle(process.Thread); CloseHandle(process.Process); }
        }
        finally
        {
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
            Marshal.FreeHGlobal(environmentPointer);
        }
    }
}
