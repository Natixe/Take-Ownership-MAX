using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Tomax;

public static class TomaxTests
{
    sealed class SkippedTestException : Exception
    { public SkippedTestException(string message) : base(message) { } }
    static int passed, failed, skipped;
    static string root, backups;
    static Requester requester;
    static readonly List<string> outcomes = new List<string>();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateDirectoryW(string path, IntPtr security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sd, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[] input, int length, IntPtr output, int outputLength, out int returned, IntPtr overlapped);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateHardLinkW(string path, string existing, IntPtr security);
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    static void Test(string name, Action body)
    {
        try { body(); passed++; Console.WriteLine("PASS " + name); outcomes.Add("PASS " + name); }
        catch (SkippedTestException ex) { skipped++; Console.WriteLine("SKIP " + name + " (" + ex.Message + ")"); outcomes.Add("SKIP " + name + " : " + ex.Message); }
        catch (Exception ex) { failed++; Console.WriteLine("FAIL " + name + " : " + ex); outcomes.Add("FAIL " + name + " : " + ex.Message); }
    }
    static void Skip(string name) { skipped++; outcomes.Add("SKIP " + name); Console.WriteLine("SKIP " + name + " (administrateur requis)"); }
    static string Fixture(string name) { string path = Path.Combine(root, name); Directory.CreateDirectory(path); return path; }
    static string Security(string path) { using (var item = Native.Open(path, false, false)) return Native.ReadSecurity(item); }
    static void Write(string path, string sddl) { using (var item = Native.Open(path, true, false)) Native.WriteSecurity(item, sddl); }
    static string WithOwner(string sddl, string owner) { var sd = new RawSecurityDescriptor(sddl); sd.Owner = new SecurityIdentifier(owner); return sd.GetSddlForm(AccessControlSections.All); }
    static void Throws(Action action, string message) { try { action(); } catch { return; } throw new Exception(message); }
    static string Snapshot(string path, string mode)
    {
        string operation = Engine.CreateOperation(backups, path, mode, requester, false);
        var engine = new Engine();
        // For a single-file fixture this cancels at the inventory/apply boundary.
        engine.Progress = delegate(ProgressInfo progress) { if (progress.Phase == "Scanning") engine.CancellationRequested = true; };
        engine.Run(operation, false, false);
        return operation;
    }
    public static int Main(string[] args)
    {
        string testOutput = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".."));
        if (!testOutput.EndsWith(".test-output", StringComparison.OrdinalIgnoreCase)) throw new Exception("Executable de test attendu dans .test-output\\bin.");
        root = Path.Combine(testOutput, "run-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
        backups = Path.Combine(root, "journals");
        requester = Requester.Capture();
        bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine("Fixtures : " + root + " ; admin=" + admin);
        Test("restauration de l'etat anterieur des privileges", delegate {
            string[] names = { "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeSecurityPrivilege" };
            var before = new Dictionary<string, int>(); foreach (var name in names) before[name] = Native.PrivilegeAttributes(name);
            using (var scope = new PrivilegeScope()) { }
            foreach (var name in names) Assert(Native.PrivilegeAttributes(name) == before[name], "privilege state leaked: " + name);
        });
        using (var privileges = new PrivilegeScope())
        {
            foreach (var entry in privileges.Results) Console.WriteLine("Privilege " + entry.Key + "=" + entry.Value);
            Test("normalisation locale, UNC, racines et chemins longs", delegate {
                Assert(Native.Normalize(@"c:\a\..\b") == @"\\?\C:\b", "dot segments");
                Assert(Native.Normalize(@"\\server\share\a\..\b") == @"\\?\UNC\server\share\b", "UNC");
                Assert(Native.Normalize(@"C:\") == @"\\?\C:\", "drive root");
                Assert(Native.Normalize(@"C:\" + new string('a', 300)).Length > 260, "long path");
                Assert(!Native.Within(@"\\?\C:\WindowsOther", @"\\?\C:\Windows"), "prefix boundary");
            });
            Test("rejet des peripheriques, ADS et chemins ambigus", delegate {
                foreach (string p in new[] { @"\\.\PhysicalDrive0", @"\\?\GLOBALROOT\Device\x", @"C:\file:stream", @"C:relative", @"C:\..\x", @"C:\*" })
                    Throws(delegate { Native.Normalize(p); }, "accepted: " + p);
            });
            Test("transport du compte avant UAC avec attributs des groupes", delegate {
                var copy = Requester.FromJson(requester.ToJson());
                Assert(copy.Sid == requester.Sid && copy.Groups.Length == requester.Groups.Length, "roundtrip identity");
                for (int i = 0; i < copy.Groups.Length; i++) Assert(copy.Groups[i].Attributes == requester.Groups[i].Attributes, "group attributes");
            });
            string alice = "S-1-5-21-111-222-333-1001", other = "S-1-5-21-111-222-333-1002";
            var synthetic = new Requester { Sid = alice, Groups = new[] { new TokenGroup { Sid = "S-1-1-0", Attributes = 7 } }, Restricted = new TokenGroup[0] };
            Test("purge ciblee, conservation des refus tiers et controle Authz", delegate {
                string original = "O:SYG:SYD:P(D;;FA;;;WD)(D;;FW;;;" + other + ")(A;;FA;;;SY)";
                string repaired = Native.RepairDescriptor(original, false, synthetic, false);
                Assert(repaired.Contains(other), "other deny removed");
                using (var verify = new AclVerifier(synthetic)) { Assert(!verify.FullControl(original), "original falsely allowed"); Assert(verify.FullControl(repaired), "repair not allowed"); }
            });
            Test("allow explicite prioritaire sur deny herite", delegate {
                string original = "O:SYG:SYD:(D;ID;FA;;;WD)";
                string repaired = Native.RepairDescriptor(original, true, synthetic, false);
                Assert(repaired.Contains("ID"), "inherited ACE lost");
                using (var verify = new AclVerifier(synthetic)) Assert(verify.FullControl(repaired), "canonical order incorrect");
            });
            Test("ULTIMATE protege la DACL et convertit l'heritage", delegate {
                string repaired = Native.RepairDescriptor("O:SYG:SYD:(D;ID;FA;;;WD)(A;ID;FR;;;" + other + ")", true, synthetic, true);
                var sd = new RawSecurityDescriptor(repaired);
                Assert((sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0, "inheritance not protected");
                foreach (GenericAce ace in sd.DiscretionaryAcl) Assert((ace.AceFlags & AceFlags.Inherited) == 0, "inherited flag retained");
                Assert(repaired.Contains(other), "unrelated allow lost");
            });
            Test("Authz respecte les groupes deny-only", delegate {
                var filtered = new Requester { Sid = alice, Groups = new[] { new TokenGroup { Sid = Native.Administrators, Attributes = 16 } }, Restricted = new TokenGroup[0] };
                using (var verify = new AclVerifier(filtered)) Assert(!verify.FullControl("O:SYG:SYD:(A;;FA;;;BA)"), "deny-only group granted access");
            });
            Test("DACL nulle et DACL vide restent distinctes", delegate {
                string empty = "O:SYG:SYD:P";
                string nullDacl = "O:SYG:SYD:NO_ACCESS_CONTROL";
                Assert(!Native.Equivalent(empty, nullDacl), "empty equals null");
                using (var verify = new AclVerifier(synthetic)) { Assert(verify.FullControl(nullDacl), "null DACL"); Assert(!verify.FullControl(empty), "empty DACL"); }
            });
            Test("enumeration native par handle", delegate {
                string dir = Fixture("enumeration"); File.WriteAllText(Path.Combine(dir, "one.txt"), "one"); Directory.CreateDirectory(Path.Combine(dir, "sub"));
                using (var item = Native.Open(dir, false, true)) {
                    int count = 0; foreach (var child in Native.Children(item)) count++;
                    Assert(count == 2, "native entries: " + count); Assert(Native.FileSystem(item) == "NTFS" || Native.FileSystem(item) == "ReFS", "filesystem");
                }
            });
            if (admin)
                Test("ecriture du parent sans propagation aux enfants, puis restauration", delegate {
                    string dir = Fixture("no-propagation"), child = Path.Combine(dir, "child.txt"); File.WriteAllText(child, "unchanged");
                    string beforeParent = Security(dir), beforeChild = Security(child);
                    string repaired = WithOwner(Native.RepairDescriptor(beforeParent, true, requester, true), requester.Sid);
                    try { Write(dir, repaired); Assert(Native.Equivalent(beforeChild, Security(child)), "parent write changed child ACL before its backup"); }
                    finally { Write(dir, beforeParent); }
                    Assert(Native.Equivalent(beforeParent, Security(dir)), "parent restore failed");
                    Assert(File.ReadAllText(child) == "unchanged", "file content changed");
                });
            else Skip("ecriture du parent sans propagation aux enfants, puis restauration");
            Test("objets de plus de 260 caracteres", delegate {
                string current = Native.Normalize(Fixture("long-path"));
                for (int i = 0; i < 6; i++) { current += "\\" + new string((char)('a' + i), 48); if (!CreateDirectoryW(current, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
                string file = current + "\\fichier.txt";
                using (var handle = CreateFileW(file, 0x40000000, 3, IntPtr.Zero, 2, 0, IntPtr.Zero)) Assert(!handle.IsInvalid, "create long file");
                string original = Security(file);
                if (admin) { Write(file, WithOwner(Native.RepairDescriptor(original, false, requester, false), requester.Sid)); Write(file, original); }
                using (var item = Native.Open(current, false, true)) Assert(new List<string>(Native.Children(item)).Count == 1, "long enumeration");
            });
            Test("jonctions exclues et redirections intermediaires refusees", delegate {
                string dir = Fixture("junction"), outside = Fixture("junction-destination"), link = Path.Combine(dir, "link"); Directory.CreateDirectory(link);
                string file = Path.Combine(outside, "untouched.txt"); File.WriteAllText(file, "untouched"); string before = Security(file);
                CreateJunction(link, outside);
                using (var item = Native.Open(link, false, false)) Assert(item.IsReparsePoint, "not detected as reparse point");
                Throws(delegate { using (var item = Native.Open(Path.Combine(link, "untouched.txt"), true, false)) { } }, "intermediate junction followed");
                string operation = Engine.CreateOperation(backups, dir, "Repair", requester, false);
                var report = new Engine().Run(operation, false, false);
                Assert(report.Skipped == 1 && report.Inventoried == 1, "junction traversed"); Assert(Native.Equivalent(before, Security(file)), "outside ACL changed");
            });
            Test("journal corrompu refuse avant modification", delegate {
                string file = Path.Combine(Fixture("corruption"), "a.txt"); File.WriteAllText(file, "a"); string before = Security(file);
                string operation = Snapshot(file, "Repair");
                using (var stream = new FileStream(Path.Combine(operation, "backup.tomax"), FileMode.Open, FileAccess.Write)) { stream.Position = 10; stream.WriteByte(0); }
                Throws(delegate { new Engine().Run(operation, false, false); }, "corrupt backup accepted"); Assert(Native.Equivalent(before, Security(file)), "corruption changed target");
            });
            Test("liens physiques exclus sans modifier leur autre nom", delegate {
                string dir = Fixture("hardlinks"), otherDir = Fixture("hardlink-outside"), file = Path.Combine(otherDir, "source.txt");
                File.WriteAllText(file, "original"); string before = Security(file);
                if (!CreateHardLinkW(Native.Normalize(Path.Combine(dir, "alias.txt")), Native.Normalize(file), IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var report = new Engine().Run(Engine.CreateOperation(backups, dir, "Repair", requester, false), false, false);
                Assert(report.Skipped == 1 && report.Inventoried == 1 && Native.Equivalent(before, Security(file)), "hardlink scope escaped");
            });
            Test("fichier disparu conserve dans les echecs", delegate {
                string file = Path.Combine(Fixture("missing"), "a.txt"); File.WriteAllText(file, "a");
                // Keep the root directory, remove a child at the completed scan boundary.
                string dir = Path.GetDirectoryName(file), operation = Engine.CreateOperation(backups, dir, "Repair", requester, false);
                var engine = new Engine(); engine.Progress = delegate(ProgressInfo p) { if (p.Phase == "Scanning" && p.Processed == 2) engine.CancellationRequested = true; };
                engine.Run(operation, false, false); File.Delete(file);
                var report = new Engine().Run(operation, false, false);
                Assert(report.Failed >= 1 && !report.Complete && report.Processed == 2, "missing object silently discarded");
            });
            Test("verrou de contenu distingue des permissions", delegate {
                string dir = Fixture("scan-locked"), file = Path.Combine(dir, "busy.txt"); File.WriteAllText(file, "a");
                using (var locked = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) {
                    var report = new Engine().Run(Engine.CreateOperation(backups, dir, "Repair", requester, false), false, false);
                    Assert(report.ScanFailed == 0 && report.Inventoried == 2 && report.Failed >= 1 && !report.Complete, "content lock confused with metadata access");
                }
            });
            Test("Restart Manager identifie le processus de test", delegate {
                string file = Path.Combine(Fixture("locks"), "busy.txt"); File.WriteAllText(file, "a");
                try {
                    using (var locked = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) {
                        var processes = LockManager.List(file); bool found = false;
                        foreach (var process in processes) if (process.ProcessId == System.Diagnostics.Process.GetCurrentProcess().Id) found = true;
                        Assert(found, "locking process absent");
                        Throws(delegate { LockManager.CloseApproved(file, processes); }, "self termination allowed");
                    }
                }
                catch (Win32Exception ex) {
                    if (!admin && ex.NativeErrorCode == 29) throw new SkippedTestException("Restart Manager indisponible dans cette session Windows (erreur 29)");
                    throw;
                }
            });
            Test("verrou exclusif du journal", delegate {
                string file = Path.Combine(Fixture("operation-lock"), "a.txt"); File.WriteAllText(file, "a"); string operation = Snapshot(file, "Repair");
                using (var locked = new FileStream(Path.Combine(operation, "operation.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    Throws(delegate { new Engine().Run(operation, false, false); }, "concurrent operation allowed");
            });
            if (admin)
            {
                Test("reparation privilegiee d'un arbre refuse et restauration", delegate {
                    string dir = Fixture("denied"), sub = Path.Combine(dir, "sub"); Directory.CreateDirectory(sub);
                    string file = Path.Combine(sub, "secret.txt"); File.WriteAllText(file, "preserved bytes");
                    Write(sub, "O:" + requester.Sid + "G:BAD:P(D;;FA;;;WD)(A;;FA;;;BA)(A;;FA;;;SY)");
                    Write(file, "O:" + requester.Sid + "G:BAD:P(D;;FA;;;WD)(A;;FA;;;BA)(A;;FA;;;SY)");
                    string a = Security(dir), b = Security(sub), c = Security(file);
                    string operation = Engine.CreateOperation(backups, dir, "Ultimate", requester, false);
                    var report = new Engine().Run(operation, false, false);
                    Assert(report.Complete && report.Succeeded == 3 && report.ScanFailed == 0, "repair incomplete: " + File.ReadAllText(Path.Combine(operation, "rapport.txt")));
                    Assert(File.ReadAllText(file) == "preserved bytes", "content unavailable");
                    var restored = new Engine().Run(operation, true, false);
                    Assert(restored.Complete && restored.Succeeded == 3, "restore incomplete");
                    Assert(Native.Equivalent(a, Security(dir)) && Native.Equivalent(b, Security(sub)) && Native.Equivalent(c, Security(file)), "original ACL mismatch");
                });
                Test("reprise des ecritures et de la restauration", delegate {
                    string dir = Fixture("resume"); for (int i = 0; i < 8; i++) File.WriteAllText(Path.Combine(dir, i + ".txt"), "data");
                    string operation = Engine.CreateOperation(backups, dir, "Repair", requester, false);
                    var engine = new Engine(); engine.Progress = delegate(ProgressInfo p) { if (p.Phase == "Applying" && p.Processed == 2) engine.CancellationRequested = true; };
                    var first = engine.Run(operation, false, false); Assert(first.Pending == 7 && !first.Complete, "cancel not checkpointed");
                    Assert(new Engine().Run(operation, false, false).Succeeded == 9, "resume lost work");
                    var restoring = new Engine(); restoring.Progress = delegate(ProgressInfo p) { if (p.Phase == "Restoring" && p.Processed == 1) restoring.CancellationRequested = true; };
                    Assert(restoring.Run(operation, true, false).Pending == 8, "restore interruption");
                    Assert(new Engine().Run(operation, false, false).Phase == "Restored", "resume forgot restore direction");
                });
                Test("conflit de restauration preserve les nouvelles permissions", delegate {
                    string file = Path.Combine(Fixture("conflict"), "a.txt"); File.WriteAllText(file, "a");
                    string operation = Engine.CreateOperation(backups, file, "Repair", requester, false);
                    Assert(new Engine().Run(operation, false, false).Complete, "initial repair");
                    string changed = "O:" + requester.Sid + "G:BAD:P(A;;FA;;;" + requester.Sid + ")(A;;FA;;;BA)(A;;FR;;;WD)";
                    Write(file, changed);
                    var report = new Engine().Run(operation, true, false);
                    Assert(report.Failed == 1 && !report.Complete && Native.Equivalent(changed, Security(file)), "concurrent ACL overwritten");
                    Assert(new Engine().Run(operation, true, true).Complete, "explicit overwrite failed");
                });
                Test("remplacement d'un fichier refuse", delegate {
                    string dir = Fixture("replaced"), file = Path.Combine(dir, "a.txt"); File.WriteAllText(file, "a");
                    string operation = Engine.CreateOperation(backups, dir, "Repair", requester, false);
                    var scan = new Engine(); scan.Progress = delegate(ProgressInfo p) { if (p.Phase == "Scanning" && p.Processed == 2) scan.CancellationRequested = true; };
                    scan.Run(operation, false, false); File.Delete(file); File.WriteAllText(file, "replacement"); File.SetCreationTimeUtc(file, DateTime.UtcNow.AddDays(-3));
                    string before = Security(file); var report = new Engine().Run(operation, false, false);
                    Assert(report.Failed == 1 && Native.Equivalent(before, Security(file)), "replacement altered");
                });
            }
            else { Skip("reparation privilegiee et restauration"); Skip("reprise des ecritures/restauration"); Skip("conflits de restauration"); Skip("remplacement de fichier"); }
            if (Array.IndexOf(args, "--stress") >= 0)
                Test("plus de 5000 objets sans troncature", delegate {
                    string dir = Fixture("stress-5002"); for (int i = 0; i < 5002; i++) File.WriteAllText(Path.Combine(dir, i + ".txt"), "");
                    string operation = Engine.CreateOperation(backups, dir, "Repair", requester, false);
                    var engine = new Engine();
                    if (!admin) engine.Progress = delegate(ProgressInfo p) { if (p.Phase == "Scanning" && p.Processed == 5003) engine.CancellationRequested = true; };
                    var report = engine.Run(operation, false, false); Assert(report.Inventoried == 5003, "truncated inventory");
                    if (admin) { Assert(report.Complete && report.Succeeded == 5003, "truncated processing"); Assert(new Engine().Run(operation, true, false).Succeeded == 5003, "truncated restore"); }
                });
        }
        string summary = "Passed=" + passed + "; Failed=" + failed + "; Skipped=" + skipped + "; Admin=" + admin + "\r\n" + String.Join("\r\n", outcomes.ToArray());
        File.WriteAllText(Path.Combine(root, "results.txt"), summary, Encoding.UTF8);
        File.WriteAllText(Path.Combine(testOutput, admin ? "latest-admin.txt" : "latest-standard.txt"), root + "\r\n" + summary, Encoding.UTF8);
        Console.WriteLine(summary.Split('\r')[0]); return failed == 0 ? 0 : 1;
    }
    static void CreateJunction(string link, string destination)
    {
        string substitute = @"\??\" + destination;
        byte[] sub = Encoding.Unicode.GetBytes(substitute), print = Encoding.Unicode.GetBytes(destination);
        byte[] data = new byte[16 + sub.Length + 2 + print.Length + 2];
        Array.Copy(BitConverter.GetBytes(0xA0000003u), 0, data, 0, 4);
        Array.Copy(BitConverter.GetBytes((ushort)(data.Length - 8)), 0, data, 4, 2);
        Array.Copy(BitConverter.GetBytes((ushort)sub.Length), 0, data, 10, 2);
        Array.Copy(BitConverter.GetBytes((ushort)(sub.Length + 2)), 0, data, 12, 2);
        Array.Copy(BitConverter.GetBytes((ushort)print.Length), 0, data, 14, 2);
        Array.Copy(sub, 0, data, 16, sub.Length); Array.Copy(print, 0, data, 18 + sub.Length, print.Length);
        using (var handle = CreateFileW(Native.Normalize(link), 0x40000000, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero))
        { int returned; if (handle.IsInvalid || !DeviceIoControl(handle, 0x900a4, data, data.Length, IntPtr.Zero, 0, out returned, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    }
}
