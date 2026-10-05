#if WINDOWS_PLATFORM
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace CSOToolbox.Client.Helpers
{
    [ComImport]
    [Guid("000214F9-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszFile, int cchMaxPath, out IntPtr pfd, int fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszName, int cchMaxName);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszDir, int cchMaxPath);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszArgs, int cchMaxPath);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszIconPath, int cchIconPath, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
        void Resolve(IntPtr hwnd, int fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    [ComImport]
    [Guid("0000010b-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPersistFile
    {
        void GetClassID(out Guid pClassID);
        [PreserveSig]
        int IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, int dwMode);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, [MarshalAs(UnmanagedType.Bool)] bool fRemember);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
        void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string ppszFileName);
    }

    [ComImport]
    [Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPropertyStore
    {
        [PreserveSig]
        int GetCount(out uint cProps);
        [PreserveSig]
        int GetAt(uint iProp, out PROPERTYKEY pkey);
        [PreserveSig]
        int GetValue(ref PROPERTYKEY key, out PROPVARIANT pv);
        [PreserveSig]
        int SetValue(ref PROPERTYKEY key, ref PROPVARIANT pv);
        [PreserveSig]
        int Commit();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROPERTYKEY
    {
        public Guid fmtid;
        public uint pid;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct PROPVARIANT
    {
        [FieldOffset(0)]
        public ushort vt;
        [FieldOffset(2)]
        public ushort wReserved1;
        [FieldOffset(4)]
        public ushort wReserved2;
        [FieldOffset(6)]
        public ushort wReserved3;
        [FieldOffset(8)]
        public IntPtr ptr;

        public static PROPVARIANT FromString(string val)
        {
            var pv = new PROPVARIANT();
            pv.vt = 31; // VT_LPWSTR
            pv.ptr = Marshal.StringToCoTaskMemUni(val);
            return pv;
        }

        public void Dispose()
        {
            if (vt == 31 && ptr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(ptr);
                ptr = IntPtr.Zero;
            }
        }
    }

    public static class ShellLinkHelper
    {
        private static void WriteLog(string message, Exception? ex = null)
        {
            Console.WriteLine($"[ShellLinkHelper] {message}");
            if (ex != null)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("ReflectionAnalysis", "IL2072:TypeMatchesExpectedPublicParameterlessConstructor", Justification = "ShellLink is a COM CoClass which has a parameterless constructor.")]
        public static void CreateShortcut(string shortcutPath, string targetPath, string arguments, string appUserModelId)
        {
            WriteLog($"Creating shortcut. Target: {targetPath}, ShortcutPath: {shortcutPath}, AUMID: {appUserModelId}");

            WriteLog("Getting CLSID for ShellLink COM object...");
#pragma warning disable CA1416 // Supported on Windows only
            var shellLinkType = Type.GetTypeFromCLSID(new Guid("00021401-0000-0000-C000-000000000046"), true)!;
#pragma warning restore CA1416
            
            WriteLog("Activating ShellLink COM object...");
            var linkObject = Activator.CreateInstance(shellLinkType);
            if (linkObject == null)
            {
                throw new InvalidOperationException("Failed to activate ShellLink COM object (returned null).");
            }
            var link = (IShellLinkW)linkObject;

            WriteLog("Setting path...");
            link.SetPath(targetPath);
            if (!string.IsNullOrEmpty(arguments))
            {
                WriteLog($"Setting arguments: {arguments}");
                link.SetArguments(arguments);
            }

            WriteLog("Casting to IPropertyStore...");
            var store = (IPropertyStore)linkObject;
            var key = new PROPERTYKEY
            {
                fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"),
                pid = 5
            };

            WriteLog("Creating PROPVARIANT for AppUserModelID...");
            var pv = PROPVARIANT.FromString(appUserModelId);
            try
            {
                WriteLog("Setting AUMID in Property Store...");
                int hr = store.SetValue(ref key, ref pv);
                if (hr < 0)
                {
                    Marshal.ThrowExceptionForHR(hr);
                }
                WriteLog("Committing property store changes...");
                hr = store.Commit();
                if (hr < 0)
                {
                    Marshal.ThrowExceptionForHR(hr);
                }
            }
            finally
            {
                pv.Dispose();
            }

            WriteLog("Casting to IPersistFile...");
            var file = (IPersistFile)linkObject;
            
            WriteLog("Saving shortcut file...");
            file.Save(shortcutPath, true);
            WriteLog("Shortcut successfully saved!");
        }

        public static void RegisterShortcutIfNeeded()
        {
            try
            {
                WriteLog("Starting shortcut registration...");
                var shortcutPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Windows\Start Menu\Programs\CSOToolbox.lnk"
                );

                var targetPath = Environment.ProcessPath;
                WriteLog($"ProcessPath: {targetPath}");
                if (string.IsNullOrEmpty(targetPath))
                {
                    WriteLog("ProcessPath is null or empty. Skipping registration.");
                    return;
                }

                var parentDir = Path.GetDirectoryName(shortcutPath);
                if (!string.IsNullOrEmpty(parentDir))
                {
                    WriteLog($"Creating/Verifying parent directory: {parentDir}");
                    Directory.CreateDirectory(parentDir);
                }
                CreateShortcut(shortcutPath, targetPath, "", "CSOToolbox");
            }
            catch (Exception ex)
            {
                WriteLog("Failed to register shortcut with exception.", ex);
                Console.WriteLine($"[ShellLinkHelper] Failed to register shortcut: {ex.Message}");
            }
        }
    }
}
#endif
