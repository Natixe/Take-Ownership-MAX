// Windows PowerShell 5.1 / .NET Framework 4.x, C# 5 compatible.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Tomax
{
    [DataContract] public class TokenGroup
    {
        [DataMember] public string Sid;
        [DataMember] public uint Attributes;
    }
    [DataContract] public class Requester
    {
        [DataMember] public string Sid;
        [DataMember] public TokenGroup[] Groups;
        [DataMember] public TokenGroup[] Restricted;
        public string ToJson() { return Json.Encode(this); }
        public static Requester FromJson(string json) { return Json.Decode<Requester>(json); }
        public static Requester Capture()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                return new Requester { Sid = identity.User.Value,
                    Groups = Native.TokenGroups(identity.Token, 2), Restricted = Native.TokenGroups(identity.Token, 11) };
        }
        public HashSet<string> DenySids()
        {
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Sid, "S-1-5-32-544" };
            foreach (TokenGroup g in Groups ?? new TokenGroup[0])
                if ((g.Attributes & (4u | 16u)) != 0) result.Add(g.Sid);
            foreach (TokenGroup g in Restricted ?? new TokenGroup[0]) result.Add(g.Sid);
            return result;
        }
    }

    public sealed class PrivilegeScope : IDisposable
    {
        private IntPtr token;
        private readonly List<Native.TokenPrivileges> previous = new List<Native.TokenPrivileges>();
        public readonly Dictionary<string, int> Results = new Dictionary<string, int>();
        public PrivilegeScope()
        {
            if (!Native.OpenProcessToken(Native.GetCurrentProcess(), 0x28, out token))
                throw Native.Error("OpenProcessToken");
            foreach (string name in new[] { "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeSecurityPrivilege" })
            {
                Native.Luid luid;
                if (!Native.LookupPrivilegeValue(null, name, out luid)) { Results[name] = Marshal.GetLastWin32Error(); continue; }
                var desired = new Native.TokenPrivileges { Count = 1, Luid = luid, Attributes = 2 };
                Native.TokenPrivileges old;
                uint length;
                bool ok = Native.AdjustTokenPrivileges(token, false, ref desired, (uint)Marshal.SizeOf(typeof(Native.TokenPrivileges)), out old, out length);
                int error = Marshal.GetLastWin32Error();
                Results[name] = ok ? error : (error == 0 ? 1 : error);
                if (ok && error == 0) previous.Add(old);
            }
        }
        public void Dispose()
        {
            if (token == IntPtr.Zero) return;
            foreach (var saved in previous)
            {
                var old = saved; Native.TokenPrivileges ignored; uint length;
                Native.AdjustTokenPrivileges(token, false, ref old, (uint)Marshal.SizeOf(typeof(Native.TokenPrivileges)), out ignored, out length);
            }
            Native.CloseHandle(token); token = IntPtr.Zero;
        }
    }

    public sealed class ObjectHandle : IDisposable
    {
        public SafeFileHandle Handle;
        public string Path, Id;
        public uint Attributes, Links;
        public bool IsDirectory { get { return (Attributes & 16) != 0; } }
        public bool IsReparsePoint { get { return (Attributes & 0x400) != 0; } }
        public void Dispose() { if (Handle != null) Handle.Dispose(); }
    }

    public static class Native
    {
        public const int FullControl = 0x001f01ff;
        public const string Administrators = "S-1-5-32-544";
        [StructLayout(LayoutKind.Sequential)] internal struct Luid { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)] internal struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] internal struct SidAttributes { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct FileInfo
        {
            public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool CloseHandle(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool LookupPrivilegeValue(string system, string name, out Luid value);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TokenPrivileges state, uint size, out TokenPrivileges previous, out uint required);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int size, out int required);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, IntPtr data, uint size);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder label, uint labelSize, out uint serial, out uint maxComponent, out uint flags, StringBuilder fs, uint fsSize);
        [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle handle, int kind, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(SafeFileHandle handle, int kind, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
        [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr sd);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetSecurityDescriptorOwner(IntPtr sd, out IntPtr owner, out bool defaulted);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool defaulted);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);

        internal static Win32Exception Error(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(), operation); }
        internal static void Check(uint code, string operation) { if (code != 0) throw new Win32Exception((int)code, operation + " (Windows " + code + " : " + new Win32Exception((int)code).Message + ")"); }
        public static string Normalize(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) throw new ArgumentException("Chemin vide.");
            string p = path.Replace('/', '\\');
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p.Substring(8);
            else if (p.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) p = p.Substring(4);
            if (p.StartsWith(@"\\.\") || p.IndexOfAny(new[] { '*', '?', '"', '\0', '\r', '\n' }) >= 0)
                throw new ArgumentException("Chemin de peripherique ou caracteres interdits.");
            string root; string tail;
            if (p.StartsWith(@"\\"))
            {
                string[] parts = p.Substring(2).Split('\\');
                if (parts.Length < 2 || parts[0].Length == 0 || parts[1].Length == 0 || parts[0] == "." || parts[1] == "." || parts[0] == ".." || parts[1] == "..")
                    throw new ArgumentException("Un chemin UNC doit inclure serveur et partage.");
                root = @"\\" + parts[0] + "\\" + parts[1] + "\\";
                tail = String.Join("\\", parts, 2, parts.Length - 2);
            }
            else
            {
                if (p.Length < 3 || !Char.IsLetter(p[0]) || p[1] != ':' || p[2] != '\\')
                    throw new ArgumentException("Utilisez un chemin absolu, par exemple C:\\Donnees.");
                root = Char.ToUpperInvariant(p[0]) + @":\"; tail = p.Substring(3);
            }
            if (tail.Contains(":")) throw new ArgumentException("Les flux alternatifs NTFS ne sont pas des cibles valides.");
            var segments = new List<string>();
            foreach (string part in tail.Split('\\'))
            {
                if (part == "" || part == ".") continue;
                if (part == "..") { if (segments.Count == 0) throw new ArgumentException("Chemin hors racine."); segments.RemoveAt(segments.Count - 1); }
                else segments.Add(part);
            }
            p = root + String.Join("\\", segments.ToArray());
            if (p.Length > 32000) throw new PathTooLongException();
            return p.StartsWith(@"\\") ? @"\\?\UNC\" + p.Substring(2) : @"\\?\" + p;
        }
        public static string Display(string path) { return path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ? @"\\" + path.Substring(8) : path.StartsWith(@"\\?\") ? path.Substring(4) : path; }
        public static bool Within(string path, string root)
        {
            return path.Equals(root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }
        public static ObjectHandle Open(string path, bool write, bool enumerate)
        {
            path = Normalize(path);
            // MAXIMUM_ALLOWED suppresses SetSecurityInfo's automatic child propagation.
            // Every existing child is backed up and changed separately. Share-delete is
            // deliberately absent: an opened object cannot be replaced during the write.
            uint access = write ? 0x02000000u : 0x00020080u;
            if (enumerate) access |= 1;
            var h = CreateFileW(path, access, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            if (h.IsInvalid) { int error = Marshal.GetLastWin32Error(); h.Dispose(); throw new Win32Exception(error, "Ouverture : " + Display(path)); }
            try
            {
                FileInfo info;
                if (!GetFileInformationByHandle(h, out info)) throw Error("Identite du fichier");
                var buffer = new StringBuilder(32768);
                uint length = GetFinalPathNameByHandleW(h, buffer, (uint)buffer.Capacity, 0);
                if (length == 0 || length >= buffer.Capacity) throw Error("Resolution du chemin reel");
                string actual = Normalize(buffer.ToString());
                // Reject intermediate junctions as well as terminal reparse points.
                if (!actual.Equals(path, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Le chemin traverse une redirection : " + Display(path) + " -> " + Display(actual));
                string id;
                IntPtr idBuffer = Marshal.AllocHGlobal(24);
                try
                {
                    if (GetFileInformationByHandleEx(h, 18, idBuffer, 24))
                    { byte[] bytes = new byte[24]; Marshal.Copy(idBuffer, bytes, 0, bytes.Length); id = BitConverter.ToString(bytes); }
                    else id = info.Volume.ToString("X8") + ":" + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8");
                }
                finally { Marshal.FreeHGlobal(idBuffer); }
                id += ":" + info.Creation.dwHighDateTime.ToString("X8") + info.Creation.dwLowDateTime.ToString("X8");
                return new ObjectHandle { Handle = h, Path = actual, Id = id, Attributes = info.Attributes, Links = info.Links };
            }
            catch { h.Dispose(); throw; }
        }
        public static string FileSystem(ObjectHandle item)
        {
            uint serial, max, flags; var fs = new StringBuilder(64);
            if (!GetVolumeInformationByHandleW(item.Handle, null, 0, out serial, out max, out flags, fs, 64)) throw Error("Systeme de fichiers");
            if ((flags & 8) == 0) throw new NotSupportedException("Le volume " + fs + " ne gere pas les ACL persistantes.");
            return fs.ToString();
        }
        public static IEnumerable<string> Children(ObjectHandle directory)
        {
            if (directory.IsReparsePoint) yield break;
            const int capacity = 65536;
            IntPtr buffer = Marshal.AllocHGlobal(capacity);
            try
            {
                while (true)
                {
                    if (!GetFileInformationByHandleEx(directory.Handle, 10, buffer, capacity))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 18) yield break;
                        throw new Win32Exception(error, "Enumeration : " + Display(directory.Path));
                    }
                    int offset = 0;
                    while (true)
                    {
                        IntPtr entry = IntPtr.Add(buffer, offset);
                        int next = Marshal.ReadInt32(entry, 0), bytes = Marshal.ReadInt32(entry, 60);
                        if (bytes < 0 || (bytes & 1) != 0 || offset + 104 + bytes > capacity) throw new IOException("Enumeration native invalide.");
                        string name = Marshal.PtrToStringUni(IntPtr.Add(entry, 104), bytes / 2);
                        if (name != "." && name != "..") yield return directory.Path.TrimEnd('\\') + "\\" + name;
                        if (next == 0) break;
                        if (next < 104 || offset + next >= capacity) throw new IOException("Offset d'enumeration invalide.");
                        offset += next;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        public static string ReadSecurity(ObjectHandle item)
        {
            IntPtr owner, group, dacl, sacl, sd;
            Check(GetSecurityInfo(item.Handle, 1, 7, out owner, out group, out dacl, out sacl, out sd), "Lecture du descripteur");
            try
            {
                byte[] bytes = new byte[GetSecurityDescriptorLength(sd)]; Marshal.Copy(sd, bytes, 0, bytes.Length);
                return new RawSecurityDescriptor(bytes, 0).GetSddlForm(AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
            }
            finally { LocalFree(sd); }
        }
        public static void WriteSecurity(ObjectHandle item, string sddl)
        {
            var sd = new RawSecurityDescriptor(sddl); byte[] bytes = new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes, 0);
            GCHandle pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                IntPtr owner, dacl; bool ignored, present;
                if (!GetSecurityDescriptorOwner(pin.AddrOfPinnedObject(), out owner, out ignored) ||
                    !GetSecurityDescriptorDacl(pin.AddrOfPinnedObject(), out present, out dacl, out ignored)) throw Error("Descripteur invalide");
                bool wasProtected = (new RawSecurityDescriptor(ReadSecurity(item)).ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
                uint protection = (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 ? 0x80000000u : (wasProtected ? 0x20000000u : 0u);
                // Only OWNER and DACL change; group, audit and integrity label remain untouched.
                Check(SetSecurityInfo(item.Handle, 1, 5u | protection, owner, IntPtr.Zero, dacl, IntPtr.Zero), "Ecriture proprietaire / DACL");
            }
            finally { pin.Free(); }
        }
        public static string RepairDescriptor(string original, bool directory, Requester requester, bool isolate)
        {
            var sd = new RawSecurityDescriptor(original);
            // A null/absent DACL already grants everyone access. Preserve that semantic.
            if (sd.DiscretionaryAcl == null) { sd.Owner = new SecurityIdentifier(Administrators); return sd.GetSddlForm(AccessControlSections.All); }
            HashSet<string> denySids = requester.DenySids();
            var denies = new List<GenericAce>(); var allows = new List<GenericAce>(); var inherited = new List<GenericAce>();
            foreach (GenericAce source in sd.DiscretionaryAcl)
            {
                GenericAce ace = source.Copy();
                if (isolate) ace.AceFlags &= ~AceFlags.Inherited;
                var qualified = ace as QualifiedAce;
                bool isInherited = (ace.AceFlags & AceFlags.Inherited) != 0;
                if (!isInherited && qualified != null && qualified.AceQualifier == AceQualifier.AccessDenied && denySids.Contains(qualified.SecurityIdentifier.Value))
                {
                    qualified.AccessMask = MapMask(qualified.AccessMask) & ~FullControl;
                    if (qualified.AccessMask == 0) continue;
                }
                if (isInherited) inherited.Add(ace);
                else if (qualified != null && qualified.AceQualifier == AceQualifier.AccessDenied) denies.Add(ace);
                else allows.Add(ace);
            }
            AceFlags flags = directory ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.None;
            foreach (string sid in new HashSet<string> { requester.Sid, Administrators })
            {
                bool covered = false;
                foreach (var entry in allows)
                {
                    var ace = entry as CommonAce;
                    if (ace != null && !ace.IsCallback && ace.AceFlags == flags && ace.SecurityIdentifier.Value == sid && ace.AceQualifier == AceQualifier.AccessAllowed)
                    { ace.AccessMask = MapMask(ace.AccessMask) | FullControl; covered = true; break; }
                }
                if (!covered) allows.Add(new CommonAce(flags, AceQualifier.AccessAllowed, FullControl, new SecurityIdentifier(sid), false, null));
            }
            var acl = new RawAcl(sd.DiscretionaryAcl.Revision, denies.Count + allows.Count + inherited.Count);
            foreach (var list in new[] { denies, allows, inherited }) foreach (var ace in list) acl.InsertAce(acl.Count, ace);
            sd.DiscretionaryAcl = acl; sd.Owner = new SecurityIdentifier(Administrators);
            if (isolate) sd.SetFlags(sd.ControlFlags | ControlFlags.DiscretionaryAclProtected);
            return sd.GetSddlForm(AccessControlSections.All);
        }
        internal static int MapMask(int mask)
        {
            uint value = unchecked((uint)mask);
            if ((value & 0x80000000) != 0) value |= 0x120089;
            if ((value & 0x40000000) != 0) value |= 0x120116;
            if ((value & 0x20000000) != 0) value |= 0x1200a0;
            if ((value & 0x10000000) != 0) value |= FullControl;
            return (int)(value & 0x0fffffff);
        }
        public static bool Equivalent(string a, string b)
        {
            var x = new RawSecurityDescriptor(a); var y = new RawSecurityDescriptor(b);
            if (!Object.Equals(x.Owner, y.Owner) || ((x.ControlFlags ^ y.ControlFlags) & ControlFlags.DiscretionaryAclProtected) != 0) return false;
            if (x.DiscretionaryAcl == null || y.DiscretionaryAcl == null) return x.DiscretionaryAcl == y.DiscretionaryAcl;
            byte[] ax = new byte[x.DiscretionaryAcl.BinaryLength], ay = new byte[y.DiscretionaryAcl.BinaryLength];
            x.DiscretionaryAcl.GetBinaryForm(ax, 0); y.DiscretionaryAcl.GetBinaryForm(ay, 0);
            return Convert.ToBase64String(ax) == Convert.ToBase64String(ay);
        }
        internal static TokenGroup[] TokenGroups(IntPtr token, int kind)
        {
            int size; GetTokenInformation(token, kind, IntPtr.Zero, 0, out size);
            if (size == 0) throw Error("Taille des groupes du jeton");
            IntPtr memory = Marshal.AllocHGlobal(size);
            try
            {
                if (!GetTokenInformation(token, kind, memory, size, out size)) throw Error("Groupes du jeton");
                int count = Marshal.ReadInt32(memory), offset = IntPtr.Size == 8 ? 8 : 4;
                var groups = new TokenGroup[count]; int stride = Marshal.SizeOf(typeof(SidAttributes));
                for (int i = 0; i < count; i++)
                {
                    var item = (SidAttributes)Marshal.PtrToStructure(IntPtr.Add(memory, offset + i * stride), typeof(SidAttributes));
                    groups[i] = new TokenGroup { Sid = new SecurityIdentifier(item.Sid).Value, Attributes = item.Attributes };
                }
                return groups;
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
        internal static int PrivilegeAttributes(string name)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                Luid requested; if (!LookupPrivilegeValue(null, name, out requested)) throw Error("Privilege inconnu");
                int size; GetTokenInformation(identity.Token, 3, IntPtr.Zero, 0, out size);
                IntPtr data = Marshal.AllocHGlobal(size);
                try
                {
                    if (!GetTokenInformation(identity.Token, 3, data, size, out size)) throw Error("Lecture des privileges");
                    int count = Marshal.ReadInt32(data);
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr entry = IntPtr.Add(data, 4 + i * 12);
                        if (unchecked((uint)Marshal.ReadInt32(entry)) == requested.Low && Marshal.ReadInt32(entry, 4) == requested.High) return Marshal.ReadInt32(entry, 8);
                    }
                    return -1;
                }
                finally { Marshal.FreeHGlobal(data); }
            }
        }
    }

    public sealed class AclVerifier : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)] struct Request { public uint Desired; public IntPtr PrincipalSelf, ObjectTypes; public uint Count; public IntPtr Optional; }
        [StructLayout(LayoutKind.Sequential)] struct Reply { public uint Count; public IntPtr Granted, Sacl, Errors; }
        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool AuthzInitializeResourceManager(uint flags, IntPtr access, IntPtr compute, IntPtr free, string name, out IntPtr manager);
        [DllImport("authz.dll", SetLastError = true)] static extern bool AuthzInitializeContextFromSid(uint flags, IntPtr sid, IntPtr manager, IntPtr expiry, Native.Luid id, IntPtr dynamicArgs, out IntPtr context);
        [DllImport("authz.dll", SetLastError = true)] static extern bool AuthzAddSidsToContext(IntPtr context, Native.SidAttributes[] groups, uint count, Native.SidAttributes[] restricted, uint restrictedCount, out IntPtr next);
        [DllImport("authz.dll", SetLastError = true)] static extern bool AuthzAccessCheck(uint flags, IntPtr context, ref Request request, IntPtr audit, byte[] descriptor, IntPtr optional, uint optionalCount, ref Reply reply, IntPtr results);
        [DllImport("authz.dll")] static extern bool AuthzFreeContext(IntPtr context);
        [DllImport("authz.dll")] static extern bool AuthzFreeResourceManager(IntPtr manager);
        IntPtr manager, context;
        public AclVerifier(Requester requester)
        {
            var allocations = new List<IntPtr>();
            try
            {
                if (!AuthzInitializeResourceManager(1, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, "Take Ownership MAX", out manager)) throw Native.Error("AuthzInitializeResourceManager");
                IntPtr sid = AllocateSid(requester.Sid, allocations);
                if (!AuthzInitializeContextFromSid(2, sid, manager, IntPtr.Zero, new Native.Luid(), IntPtr.Zero, out context)) throw Native.Error("AuthzInitializeContextFromSid");
                Native.SidAttributes[] groups = Groups(requester.Groups, allocations), restricted = Groups(requester.Restricted, allocations);
                IntPtr next;
                if (!AuthzAddSidsToContext(context, groups, (uint)groups.Length, restricted, (uint)restricted.Length, out next)) throw Native.Error("AuthzAddSidsToContext");
                AuthzFreeContext(context); context = next;
            }
            catch { Dispose(); throw; }
            finally { foreach (IntPtr memory in allocations) Marshal.FreeHGlobal(memory); }
        }
        static IntPtr AllocateSid(string value, List<IntPtr> allocations)
        {
            var sid = new SecurityIdentifier(value); byte[] bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            IntPtr memory = Marshal.AllocHGlobal(bytes.Length); allocations.Add(memory); Marshal.Copy(bytes, 0, memory, bytes.Length); return memory;
        }
        static Native.SidAttributes[] Groups(TokenGroup[] source, List<IntPtr> allocations)
        {
            source = source ?? new TokenGroup[0]; var result = new Native.SidAttributes[source.Length];
            for (int i = 0; i < source.Length; i++) result[i] = new Native.SidAttributes { Sid = AllocateSid(source[i].Sid, allocations), Attributes = source[i].Attributes };
            return result;
        }
        public bool FullControl(string sddl)
        {
            var descriptor = new RawSecurityDescriptor(sddl);
            if (descriptor.DiscretionaryAcl != null) foreach (GenericAce ace in descriptor.DiscretionaryAcl)
            { var qualified = ace as QualifiedAce; if (qualified != null) qualified.AccessMask = Native.MapMask(qualified.AccessMask); }
            byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
            IntPtr granted = Marshal.AllocHGlobal(4), error = Marshal.AllocHGlobal(4);
            try
            {
                Marshal.WriteInt32(granted, 0); Marshal.WriteInt32(error, 0);
                var request = new Request { Desired = Native.FullControl };
                var reply = new Reply { Count = 1, Granted = granted, Errors = error };
                if (!AuthzAccessCheck(0, context, ref request, IntPtr.Zero, bytes, IntPtr.Zero, 0, ref reply, IntPtr.Zero)) throw Native.Error("AuthzAccessCheck");
                return Marshal.ReadInt32(error) == 0 && (Marshal.ReadInt32(granted) & Native.FullControl) == Native.FullControl;
            }
            finally { Marshal.FreeHGlobal(granted); Marshal.FreeHGlobal(error); }
        }
        public void Dispose()
        { if (context != IntPtr.Zero) { AuthzFreeContext(context); context = IntPtr.Zero; } if (manager != IntPtr.Zero) { AuthzFreeResourceManager(manager); manager = IntPtr.Zero; } }
    }
}
