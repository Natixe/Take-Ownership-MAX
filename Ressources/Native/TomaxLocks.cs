using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;

namespace Tomax
{
    [DataContract] public class LockingProcess
    {
        [DataMember] public int ProcessId;
        [DataMember] public string Name, Service, Type;
        [DataMember] public bool Restartable;
        [DataMember] public long StartTime;
    }
    public static class LockManager
    {
        [StructLayout(LayoutKind.Sequential)] struct UniqueProcess
        { public int Pid; public System.Runtime.InteropServices.ComTypes.FILETIME Started; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct ProcessInfo
        {
            public UniqueProcess Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string Service;
            public int Type; public uint Status, Session;
            [MarshalAs(UnmanagedType.Bool)] public bool Restartable;
        }
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmStartSession(out uint handle, int flags, StringBuilder key);
        [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint handle);
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmRegisterResources(uint handle, uint count, string[] files, uint appCount, IntPtr apps, uint serviceCount, string[] services);
        [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint handle, out uint required, ref uint count, [In, Out] ProcessInfo[] processes, ref uint reasons);
        [DllImport("rstrtmgr.dll")] static extern int RmShutdown(uint handle, uint flags, IntPtr callback);
        static uint Start(string path)
        {
            uint handle; int error = RmStartSession(out handle, 0, new StringBuilder(Guid.NewGuid().ToString("N"), 33));
            if (error != 0) throw new Win32Exception(error, "Ouverture d'une session Restart Manager (Windows " + error + " : " + new Win32Exception(error).Message + ")");
            error = RmRegisterResources(handle, 1, new[] { Native.Normalize(path) }, 0, IntPtr.Zero, 0, null);
            if (error != 0) { RmEndSession(handle); throw new Win32Exception(error, "Enregistrement Restart Manager (fichiers uniquement)."); }
            return handle;
        }
        static ProcessInfo[] Processes(uint session)
        {
            uint required = 0, count = 0, reasons = 0;
            for (int attempt = 0; attempt < 8; attempt++)
            {
                ProcessInfo[] data = count == 0 ? null : new ProcessInfo[count];
                int error = RmGetList(session, out required, ref count, data, ref reasons);
                if (error == 0) { if (data == null) return new ProcessInfo[0]; Array.Resize(ref data, (int)count); return data; }
                if (error != 234) throw new Win32Exception(error, "Liste Restart Manager");
                count = required;
            }
            throw new IOExceptionForLocks("La liste des applications change trop rapidement. Reessayez.");
        }
        static LockingProcess Convert(ProcessInfo info)
        {
            return new LockingProcess { ProcessId = info.Process.Pid, Name = info.Name, Service = info.Service, Type = info.Type.ToString(), Restartable = info.Restartable,
                StartTime = ((long)info.Process.Started.dwHighDateTime << 32) | (uint)info.Process.Started.dwLowDateTime };
        }
        public static LockingProcess[] List(string path)
        {
            uint session = Start(path);
            try { ProcessInfo[] values = Processes(session); var result = new LockingProcess[values.Length]; for (int i = 0; i < values.Length; i++) result[i] = Convert(values[i]); return result; }
            finally { RmEndSession(session); }
        }
        // UI must display List() and obtain an explicit decision before calling this.
        // The exact PID/start-time set is rechecked, so new processes aren't closed.
        public static void CloseApproved(string path, LockingProcess[] approved)
        {
            uint session = Start(path);
            try
            {
                foreach (ProcessInfo process in Processes(session))
                {
                    LockingProcess item = Convert(process); bool found = false;
                    foreach (var expected in approved) if (expected.ProcessId == item.ProcessId && expected.StartTime == item.StartTime) found = true;
                    if (!found || !String.IsNullOrEmpty(item.Service) || process.Type == 3 || process.Type == 4 || process.Type == 1000 || item.ProcessId == Process.GetCurrentProcess().Id)
                        throw new InvalidOperationException("Liste modifiee, service ou processus essentiel : fermeture refusee.");
                }
                // 0 = graceful request only. Never RmForceShutdown or TerminateProcess.
                int error = RmShutdown(session, 0, IntPtr.Zero);
                if (error != 0) throw new Win32Exception(error, "Fermeture propre refusee par une application.");
            }
            finally { RmEndSession(session); }
        }
        sealed class IOExceptionForLocks : System.IO.IOException { public IOExceptionForLocks(string message) : base(message) { } }
    }
}
