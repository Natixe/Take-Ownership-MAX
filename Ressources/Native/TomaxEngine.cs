using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Tomax
{
    public static class Json
    {
        public static string Encode<T>(T value)
        { using (var stream = new MemoryStream()) { new DataContractJsonSerializer(typeof(T)).WriteObject(stream, value); return Encoding.UTF8.GetString(stream.ToArray()); } }
        public static T Decode<T>(string value)
        { using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(value))) return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(stream); }
    }
    [DataContract] public class BackupEntry
    {
        [DataMember] public string Path, Id, Original;
        [DataMember] public bool Directory;
    }
    [DataContract] public class OperationState
    {
        [DataMember] public int Version = 3;
        [DataMember] public int BackupFormat = 1;
        [DataMember] public string Root, RootId, Mode, Phase, StartedUtc, BackupHash;
        [DataMember] public Requester Requester;
        [DataMember] public bool AllowHardLinks;
        [DataMember] public long Cursor, BackupLength, InventoryCount, ScanFailed, ScanSkipped, Processed, Succeeded, Failed, Unchanged;
    }
    [DataContract] public class EventRecord
    {
        [DataMember] public string Utc, Phase, Path, Status, Message;
        [DataMember] public int Error;
        [DataMember] public LockingProcess[] LockingProcesses;
    }
    [DataContract] public class OperationReport
    {
        [DataMember] public string OperationDirectory, Target, Phase;
        [DataMember] public long Inventoried, Processed, Succeeded, Unchanged, Failed, ScanFailed, Skipped, Pending;
        [DataMember] public bool Complete;
        [DataMember] public string Verification = "Proprietaire et DACL relus ; controle total DACL calcule par Authz avec les SID et attributs captures. Ni test EFS, ni test des verrous, ni simulation complete des strategies/claims Windows.";
    }
    public class ProgressInfo
    {
        public string Phase, Path;
        public long Processed, Total, Failed;
    }
    public sealed class Engine
    {
        public volatile bool CancellationRequested;
        public Action<ProgressInfo> Progress;
        private string operationDirectory;
        private OperationState state;
        private FileStream eventStream;

        public static void CreatePrivateDirectory(string path)
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
            bool administrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            SecurityIdentifier owner = administrator ? new SecurityIdentifier(Native.Administrators) : identity.User;
            var trusted = new HashSet<string> { owner.Value, Native.Administrators, "S-1-5-18" };
            if (Directory.Exists(path))
            {
                using (var item = Native.Open(path, false, false)) if (item.IsReparsePoint) throw new IOException("Dossier de sauvegarde redirige.");
                var existing = Directory.GetAccessControl(path);
                if (!existing.AreAccessRulesProtected || !trusted.Contains(existing.GetOwner(typeof(SecurityIdentifier)).Value))
                    throw new IOException("Le dossier de sauvegarde existant n'est pas prive : " + path);
                foreach (FileSystemAccessRule rule in existing.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    if (rule.AccessControlType == AccessControlType.Allow && !trusted.Contains(rule.IdentityReference.Value) &&
                        (rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0)
                        throw new IOException("Le dossier de sauvegarde autorise un tiers a ecrire : " + path);
                return;
            }
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(owner);
            foreach (var sid in trusted)
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(path, acl);
            }
        }
        public static string CreateOperation(string baseDirectory, string target, string mode, Requester requester, bool allowHardLinks)
        {
            if (mode != "Repair" && mode != "Ultimate") throw new ArgumentException("Mode invalide.");
            target = Native.Normalize(target);
            baseDirectory = Path.GetFullPath(baseDirectory);
            if (Native.Within(Native.Normalize(baseDirectory), target)) throw new ArgumentException("La sauvegarde doit etre situee hors de la cible.");
            CreatePrivateDirectory(baseDirectory);
            using (var baseGuard = Native.Open(baseDirectory, false, false))
            {
            CreatePrivateDirectory(baseDirectory);
            string dir = Path.Combine(baseDirectory, DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));
            CreatePrivateDirectory(dir);
            using (var root = Native.Open(target, false, false))
            {
                if (root.IsReparsePoint) throw new IOException("La cible est un lien ou une jonction. Choisissez son dossier reel.");
                Native.FileSystem(root);
                var value = new OperationState { Root = target, RootId = root.Id, Mode = mode, Requester = requester,
                    Phase = "Scanning", StartedUtc = DateTime.UtcNow.ToString("o"), AllowHardLinks = allowHardLinks };
                SaveState(dir, value);
            }
            return dir;
            }
        }
        static string DataPath(string directory, string name)
        {
            string path = Path.Combine(directory, name);
            if (File.Exists(path)) using (var item = Native.Open(Path.GetFullPath(path), false, false))
                if (item.IsReparsePoint || item.Links > 1) throw new IOException("Fichier de journal redirige ou lie : " + name);
            return path;
        }
        public static OperationState ReadState(string directory)
        {
            CreatePrivateDirectory(directory);
            using (var item = Native.Open(Path.GetFullPath(directory), false, false))
                if (item.IsReparsePoint) throw new IOException("Operation redirigee.");
            var value = Json.Decode<OperationState>(File.ReadAllText(DataPath(directory, "state.json"), Encoding.UTF8));
            if (value.Version != 3 || value.BackupFormat != 1 || value.Requester == null || value.Root != Native.Normalize(value.Root) || value.Cursor < 0 ||
                (value.Mode != "Repair" && value.Mode != "Ultimate")) throw new InvalidDataException("Operation incompatible ou invalide.");
            new SecurityIdentifier(value.Requester.Sid);
            return value;
        }
        static void SaveState(string directory, OperationState value)
        {
            string temp = DataPath(directory, "state.tmp"), target = DataPath(directory, "state.json");
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Encode(value));
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
            if (File.Exists(target)) File.Replace(temp, target, null); else File.Move(temp, target);
        }
        static void WriteRecord<T>(FileStream stream, T value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Encode(value));
            byte[] length = BitConverter.GetBytes(bytes.Length); stream.Write(length, 0, length.Length); stream.Write(bytes, 0, bytes.Length);
        }
        static T ReadRecord<T>(FileStream stream)
        {
            byte[] length = new byte[4];
            if (stream.Read(length, 0, 4) != 4) throw new InvalidDataException("Journal tronque (longueur).");
            int size = BitConverter.ToInt32(length, 0);
            if (size < 1 || size > 1048576 || size > stream.Length - stream.Position) throw new InvalidDataException("Journal tronque ou taille invalide.");
            byte[] bytes = new byte[size]; int offset = 0;
            while (offset < size) { int read = stream.Read(bytes, offset, size - offset); if (read == 0) throw new EndOfStreamException(); offset += read; }
            return Json.Decode<T>(Encoding.UTF8.GetString(bytes));
        }
        static void WriteBackup(FileStream stream, BackupEntry entry)
        {
            long start = stream.Position; WriteRecord(stream, entry);
            byte[] length = BitConverter.GetBytes(checked((int)(stream.Position - start - 4)));
            stream.Write(length, 0, 4);
        }
        static BackupEntry ReadBackup(FileStream stream)
        {
            long start = stream.Position; BackupEntry entry = ReadRecord<BackupEntry>(stream);
            int expected = checked((int)(stream.Position - start - 4)); byte[] footer = new byte[4];
            if (stream.Read(footer, 0, 4) != 4 || BitConverter.ToInt32(footer, 0) != expected) throw new InvalidDataException("Fin d'entree de sauvegarde invalide.");
            return entry;
        }
        static BackupEntry ReadPreviousBackup(FileStream stream)
        {
            long end = stream.Position;
            if (end < 8) throw new InvalidDataException("Point de reprise inverse invalide.");
            stream.Position = end - 4; byte[] footer = new byte[4];
            if (stream.Read(footer, 0, 4) != 4) throw new EndOfStreamException();
            int size = BitConverter.ToInt32(footer, 0); long start = end - 8 - size;
            if (size < 1 || size > 1048576 || start < 0) throw new InvalidDataException("Taille d'entree inverse invalide.");
            stream.Position = start; BackupEntry entry = ReadBackup(stream);
            if (stream.Position != end) throw new InvalidDataException("Entree inverse incoherente.");
            stream.Position = start; return entry;
        }
        static string Hash(FileStream stream)
        { long position = stream.Position; stream.Position = 0; try { using (var sha = SHA256.Create()) return Convert.ToBase64String(sha.ComputeHash(stream)); } finally { stream.Position = position; } }
        void Log(string path, string status, string message, int error, LockingProcess[] lockers)
        {
            var record = new EventRecord { Utc = DateTime.UtcNow.ToString("o"), Phase = state.Phase, Path = Native.Display(path), Status = status, Message = message, Error = error, LockingProcesses = lockers };
            byte[] bytes = Encoding.UTF8.GetBytes(Json.Encode(record) + "\n"); eventStream.Write(bytes, 0, bytes.Length); eventStream.Flush(true);
        }
        void Notify(string path)
        {
            if (Progress != null) Progress(new ProgressInfo { Phase = state.Phase, Path = Native.Display(path), Processed = state.Phase == "Scanning" ? state.InventoryCount : state.Processed, Total = state.InventoryCount, Failed = state.Failed + state.ScanFailed });
        }
        static int ErrorCode(Exception exception)
        { var win32 = exception as Win32Exception; return win32 == null ? exception.HResult : win32.NativeErrorCode; }
        void Scan()
        {
            state.InventoryCount = state.ScanFailed = state.ScanSkipped = 0;
            // A interrupted inventory is rebuilt before any write. No old backup is
            // overwritten once the phase has left Scanning.
            using (var backup = new FileStream(DataPath(operationDirectory, "backup.tomax"), FileMode.Create, FileAccess.ReadWrite, FileShare.Read))
            using (var queue = new FileStream(DataPath(operationDirectory, "scan.queue"), FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            {
                WriteRecord(queue, state.Root); long cursor = 0;
                while (cursor < queue.Length)
                {
                    if (CancellationRequested) { backup.Flush(true); SaveState(operationDirectory, state); return; }
                    queue.Position = cursor; string path = ReadRecord<string>(queue); cursor = queue.Position; queue.Position = queue.Length;
                    try
                    {
                        using (var item = Native.Open(path, false, false))
                        {
                            if (item.IsReparsePoint || (!state.AllowHardLinks && !item.IsDirectory && item.Links > 1))
                            {
                                state.ScanSkipped++; Log(path, "Skipped", item.IsReparsePoint ? "Lien / jonction non suivi." : "Liens physiques : effet possible sur d'autres chemins. Option -IncludeHardLinks requise.", 0, null); continue;
                            }
                            var entry = new BackupEntry { Path = path, Id = item.Id, Directory = item.IsDirectory, Original = Native.ReadSecurity(item) };
                            WriteBackup(backup, entry); state.InventoryCount++;
                            if (item.IsDirectory)
                            {
                                using (var directory = Native.Open(path, false, true))
                                {
                                    if (directory.Id != item.Id) throw new IOException("Dossier remplace durant l'inventaire.");
                                    foreach (string child in Native.Children(directory)) WriteRecord(queue, child);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (ex is OutOfMemoryException) throw;
                        state.ScanFailed++; Log(path, "ScanFailure", ex.Message + " Sous-arbre eventuel non inventorie.", ErrorCode(ex), null);
                    }
                    Notify(path);
                }
                backup.Flush(true); state.BackupLength = backup.Length; state.BackupHash = Hash(backup);
            }
            state.Phase = "Ready"; SaveState(operationDirectory, state);
        }
        void ValidateBackup(FileStream backup)
        {
            if (backup.Length != state.BackupLength || Hash(backup) != state.BackupHash) throw new InvalidDataException("Sauvegarde incomplete ou empreinte SHA-256 incorrecte. Aucune ecriture autorisee.");
            backup.Position = 0; long count = 0; bool boundary = state.Cursor == 0;
            while (backup.Position < backup.Length)
            {
                BackupEntry entry = ReadBackup(backup);
                if (entry.Path != Native.Normalize(entry.Path) || !Native.Within(entry.Path, state.Root) || String.IsNullOrWhiteSpace(entry.Id)) throw new InvalidDataException("Entree hors cible ou identite absente.");
                new RawSecurityDescriptor(entry.Original); count++;
                if (backup.Position == state.Cursor) boundary = true;
            }
            if (count != state.InventoryCount || !boundary) throw new InvalidDataException("Compteur ou point de reprise invalide.");
        }
        public OperationReport Run(string directory, bool restore, bool overwriteChanged)
        {
            operationDirectory = Path.GetFullPath(directory);
            CreatePrivateDirectory(operationDirectory);
            using (var directoryGuard = Native.Open(operationDirectory, false, false))
            {
            CreatePrivateDirectory(operationDirectory);
            // One writer per operation; state and backup are protected by the private
            // operation directory. Root identity is checked again on every invocation.
            using (var lockFile = new FileStream(DataPath(operationDirectory, "operation.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            using (eventStream = new FileStream(DataPath(operationDirectory, "events.jsonl"), FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                state = ReadState(operationDirectory);
                if (Native.Within(Native.Normalize(operationDirectory), state.Root)) throw new IOException("Journal situe dans la cible.");
                using (var root = Native.Open(state.Root, false, false))
                {
                    if (root.IsReparsePoint || root.Id != state.RootId) throw new IOException("La cible a ete remplacee ou redirigee depuis la sauvegarde.");
                    ConsoleCancelEventHandler cancel = delegate(object sender, ConsoleCancelEventArgs args) { CancellationRequested = true; args.Cancel = true; };
                    Console.CancelKeyPress += cancel;
                    try
                    {
                        if (state.Phase == "Scanning")
                        {
                            if (restore) throw new InvalidOperationException("Inventaire interrompu : aucune permission n'a encore ete modifiee.");
                            Scan(); if (CancellationRequested) return Report();
                        }
                        bool restoring = restore || state.Phase == "Restoring" || state.Phase == "RestorePartial";
                        if (state.Phase == "Restored" && !restore) return Report();
                        using (var backup = new FileStream(DataPath(operationDirectory, "backup.tomax"), FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            ValidateBackup(backup);
                            if ((restoring && state.Phase != "Restoring") || (!restoring && state.Phase != "Applying"))
                            { state.Cursor = restoring ? 0 : backup.Length; state.Processed = state.Succeeded = state.Failed = state.Unchanged = 0; }
                            state.Phase = restoring ? "Restoring" : "Applying"; SaveState(operationDirectory, state);
                            backup.Position = state.Cursor;
                            using (var verifier = new AclVerifier(state.Requester))
                            {
                                // Repair leaves before parents: Windows may refresh a
                                // child's inherited ACEs on that child's own write.
                                // Restoration uses the opposite order (parents first).
                                while (restoring ? backup.Position < backup.Length : backup.Position > 0)
                                {
                                    if (CancellationRequested) break;
                                    BackupEntry entry = restoring ? ReadBackup(backup) : ReadPreviousBackup(backup);
                                    Apply(entry, restoring, overwriteChanged, verifier);
                                    state.Processed++; state.Cursor = backup.Position;
                                    SaveState(operationDirectory, state); Notify(entry.Path);
                                }
                            }
                            if (restoring ? state.Cursor == backup.Length : state.Cursor == 0)
                                state.Phase = restoring ? (state.Failed == 0 ? "Restored" : "RestorePartial") :
                                    (state.Failed == 0 && state.ScanFailed == 0 ? "Complete" : "Partial");
                            SaveState(operationDirectory, state);
                        }
                        return Report();
                    }
                    finally { Console.CancelKeyPress -= cancel; }
                }
            }
            }
        }
        void Apply(BackupEntry entry, bool restore, bool overwrite, AclVerifier verifier)
        {
            try
            {
                using (var item = Native.Open(entry.Path, true, false))
                {
                    if (item.Id != entry.Id || item.IsReparsePoint || item.IsDirectory != entry.Directory) throw new IOException("Objet remplace depuis la sauvegarde : operation refusee.");
                    if (!state.AllowHardLinks && !item.IsDirectory && item.Links > 1) throw new IOException("Un lien physique est apparu depuis la sauvegarde.");
                    string current = Native.ReadSecurity(item);
                    string repaired = Native.RepairDescriptor(entry.Original, entry.Directory, state.Requester, state.Mode == "Ultimate");
                    string desired = restore ? entry.Original : repaired;
                    if (!overwrite && !Native.Equivalent(current, entry.Original) && !Native.Equivalent(current, repaired))
                        throw new Win32Exception(1306, "Permissions modifiees depuis l'operation. Inspectez-les avant -OverwriteChanged.");
                    bool unchanged = Native.Equivalent(current, desired);
                    // The durable backup exists and was hash-checked before this intent.
                    if (!unchanged) { Log(entry.Path, "Intent", restore ? "Restauration" : "Reparation", 0, null); Native.WriteSecurity(item, desired); }
                    string actual = Native.ReadSecurity(item);
                    if (!Native.Equivalent(actual, desired)) throw new IOException("Les permissions relues different du resultat demande.");
                    if (!restore && !verifier.FullControl(actual)) throw new Win32Exception(5, "Controle total DACL non confirme par Authz pour le compte demandeur.");
                    Log(entry.Path, restore ? "Restored" : "AclVerified", unchanged ? "Deja conforme." : "Ecriture et relecture confirmees.", 0, null);
                    state.Succeeded++; if (unchanged) state.Unchanged++;
                }
            }
            catch (Exception ex)
            {
                if (ex is OutOfMemoryException) throw;
                int error = ErrorCode(ex); LockingProcess[] lockers = null;
                if (!entry.Directory && (error == 32 || error == 33))
                { try { lockers = LockManager.List(entry.Path); } catch { } }
                Log(entry.Path, error == 1306 ? "Conflict" : "Failure", ex.Message, error, lockers); state.Failed++;
            }
        }
        OperationReport Report()
        {
            var report = new OperationReport { OperationDirectory = operationDirectory, Target = Native.Display(state.Root), Phase = state.Phase,
                Inventoried = state.InventoryCount, Processed = state.Processed, Succeeded = state.Succeeded, Failed = state.Failed,
                Unchanged = state.Unchanged, ScanFailed = state.ScanFailed, Skipped = state.ScanSkipped,
                Pending = Math.Max(0, state.InventoryCount - state.Processed), Complete = state.Phase == "Complete" || state.Phase == "Restored" };
            File.WriteAllText(DataPath(operationDirectory, "report.json"), Json.Encode(report), new UTF8Encoding(false));
            File.WriteAllText(DataPath(operationDirectory, "rapport.txt"),
                "TAKE OWNERSHIP MAX ULTIMATE v3\r\nCible : " + report.Target + "\r\nEtat : " + report.Phase +
                "\r\nInventories : " + report.Inventoried + "\r\nTraites : " + report.Processed + "\r\nVerifies / restaures : " + report.Succeeded +
                "\r\nDont deja conformes : " + report.Unchanged + "\r\nEchecs de traitement : " + report.Failed + "\r\nEchecs d'inventaire : " + report.ScanFailed +
                "\r\nExclusions (liens) : " + report.Skipped + "\r\nEn attente : " + report.Pending + "\r\n\r\n" + report.Verification +
                "\r\nDetails horodates : events.jsonl\r\nSauvegarde : backup.tomax (ne pas supprimer)\r\n", new UTF8Encoding(true));
            return report;
        }
    }
}
