using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
//
// This code has been adapted from http://www.codeproject.com/KB/cs/lsadotnet.aspx
// The rights enumeration code came from http://www.tech-archive.net/Archive/DotNet/microsoft.public.dotnet.framework.interop/2004-11/0394.html
//
// Windows Security via .NET is covered on by Pluralsight:http://alt.pluralsight.com/wiki/default.aspx/Keith.GuideBook/HomePage.html
//
// Some code from https://github.com/iadgov/Secure-Host-Baseline/blob/master/Compliance/Scripts/Compliance.psm1
// The idea here us to use as much .NET framework functionality as possible and reduce the use of PInvoke to the minimum.
// To do: use functions instead of repeated code. Remove PInvoke for access to SIDs and accounts.

namespace LSAController
{
    // Local security rights managed by the Local Security Authority
    // See https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx
    // See https://msdn.microsoft.com/en-us/library/windows/desktop/bb545671(v=vs.85).aspx
    public class LocalSecurityAuthorityRights
    {
        // Log on as a service right
        public const string LogonAsService = "SeServiceLogonRight";
        // Log on as a batch job right
        public const string LogonAsBatchJob = "SeBatchLogonRight";
        // Interactive log on right
        public const string InteractiveLogon = "SeInteractiveLogonRight";
        // Remote Desktop log on right
        public const string RemoteDesktopLogon = "SeRemoteInteractiveLogonRight";
        // Network log on right
        public const string NetworkLogon = "SeNetworkLogonRight";
        // Generate security audit logs right
        public const string GenerateSecurityAudits = "SeAuditPrivilege";
        // Backup system right
        public const string Backup = "SeBackupPrivilege";
        // Set system time right
        public const string SetTime = "SeSystemtimePrivilege";
        // Remote shutdown right
        public const string RemoteShutdown = "SeRemoteShutdownPrivilege";
        // Replace a process-level token
        public const string ReplaceProcessLevelToken = "SeAssignPrimaryTokenPrivilege";
        // Impersonate a client after authentication
        public const string ImpersonateClientAfterAuth = "SeImpersonatePrivilege";
        // Adjust memory quotas for a process
        public const string IncreaseProcessQuota = "SeIncreaseQuotaPrivilege";
        // ct as part of the operating system
        public const string ActAsPartOfOS = "SeTcbPrivilege";


        // Deny remote Desktop log on right
        public const string DenyRemoteDesktopLogon = "SeDenyRemoteInteractiveLogonRight";
        // Deny log on as a service right
        public const string DenyLogonAsService = "SeDenyServiceLogonRight";
        // Deny log on as a batch job right
        public const string DenyLogonAsBatchJob = "SeDenyBatchLogonRight";
        // Deny interactive log on right
        public const string DenyInteractiveLogon = "SeDenyInteractiveLogonRight";
        // Deny network log on right
        public const string DenyNetworkLogon = "SeDenyNetworkLogonRight";
        /*
         *  
            SeSecurityPrivilege
            SeBackupPrivilege
            SeRestorePrivilege
            SeSystemtimePrivilege
            SeShutdownPrivilege
            SeRemoteShutdownPrivilege
            SeTakeOwnershipPrivilege
            SeDebugPrivilege
            SeSystemEnvironmentPrivilege
            SeSystemProfilePrivilege
            SeProfileSingleProcessPrivilege
            SeIncreaseBasePriorityPrivilege
            SeLoadDriverPrivilege
            SeCreatePagefilePrivilege
            SeIncreaseQuotaPrivilege
            SeChangeNotifyPrivilege
            SeUndockPrivilege
            SeManageVolumePrivilege
            SeImpersonatePrivilege
            SeCreateGlobalPrivilege
            SeTimeZonePrivilege
            SeCreateSymbolicLinkPrivilege
            SeInteractiveLogonRight
            SeNetworkLogonRight
            SeBatchLogonRight
            SeRemoteInteractiveLogonRight
            SeAssignPrimaryTokenPrivilege
            SeImpersonatePrivilege
            SeIncreaseQuotaPrivilege
            SeTcbPrivilege
         * 
         */

    }

    //
    // Provides methods the local security authority which controls user rights. Managed via secpol.msc normally.
    //
    public class LocalSecurityAuthorityController
    {
        private const int Access = (int)(
        LSA_AccessPolicy.POLICY_AUDIT_LOG_ADMIN |
        LSA_AccessPolicy.POLICY_CREATE_ACCOUNT |
        LSA_AccessPolicy.POLICY_CREATE_PRIVILEGE |
        LSA_AccessPolicy.POLICY_CREATE_SECRET |
        LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION |
        LSA_AccessPolicy.POLICY_LOOKUP_NAMES |
        LSA_AccessPolicy.POLICY_NOTIFICATION |
        LSA_AccessPolicy.POLICY_SERVER_ADMIN |
        LSA_AccessPolicy.POLICY_SET_AUDIT_REQUIREMENTS |
        LSA_AccessPolicy.POLICY_SET_DEFAULT_QUOTA_LIMITS |
        LSA_AccessPolicy.POLICY_TRUST_ADMIN |
        LSA_AccessPolicy.POLICY_VIEW_AUDIT_INFORMATION |
        LSA_AccessPolicy.POLICY_VIEW_LOCAL_INFORMATION
        );

        private const uint STATUS_ACCESS_DENIED = 0xc0000022;
        private const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        private const uint STATUS_NO_MEMORY = 0xc0000017;
        private const uint STATUS_NO_MORE_ENTRIES = 0xc000001A;

        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_ENUMERATION_INFORMATION
        {
            internal IntPtr PSid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [Flags]
        private enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        [DllImport("advapi32.dll", PreserveSig = true)]
        private static extern UInt32 LsaOpenPolicy(ref LSA_UNICODE_STRING SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, Int32 DesiredAccess, out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaAddAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, LSA_UNICODE_STRING[] UserRights, int CountOfRights);

        [DllImport("advapi32")]
        public static extern void FreeSid(IntPtr pSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true, PreserveSig = true)]
        private static extern bool LookupAccountName(string lpSystemName, string lpAccountName, IntPtr psid, ref int cbsid, StringBuilder domainName, ref int cbdomainLength, ref int use);

        [DllImport("advapi32.dll")]
        private static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll")]
        private static extern int LsaClose(IntPtr ObjectHandle);

        [DllImport("kernel32.dll")]
        private static extern int GetLastError();

        [DllImport("advapi32.dll")]
        private static extern int LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, out IntPtr UserRightsPtr, out int CountOfRights);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaEnumerateAccountsWithUserRight(IntPtr PolicyHandle, LSA_UNICODE_STRING[] UserRights, out IntPtr EnumerationBuffer, out long CountReturned);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaRemoveAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, [MarshalAs(UnmanagedType.U1)]bool AllRights, LSA_UNICODE_STRING[] UserRights, uint CountOfRights);

        private static IntPtr GetAccountSID(string accountName)
        {
            IntPtr pSid = IntPtr.Zero;
            SecurityIdentifier userSid = (SecurityIdentifier)(new System.Security.Principal.NTAccount(string.Empty, accountName)).Translate(typeof(SecurityIdentifier));
            Byte[] buffer = new Byte[userSid.BinaryLength];
            userSid.GetBinaryForm(buffer, 0);
            pSid = Marshal.AllocHGlobal(userSid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, userSid.BinaryLength);
            return pSid;
        }

        private static string GetSIDAccount(IntPtr sid)
        {
            string theAccountName;
            try
            {
                theAccountName = (new SecurityIdentifier(sid)).Translate(typeof(NTAccount)).ToString();
            }
            catch (System.Security.Principal.IdentityNotMappedException)
            {
                theAccountName = (new SecurityIdentifier(sid)).ToString();
            }
            return theAccountName;
        }

        // Returns the Local Security Authority rights granted to the account
        public IList<string> GetRightsForAccount(string accountName)
        {
            IList<string> rights = new List<string>();
            string errorMessage = string.Empty;
            long winErrorCode = 0;
            IntPtr pSid = IntPtr.Zero;

            pSid = GetAccountSID(accountName);

            //if (!LookupAccountName(string.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType))
            //{
            //    winErrorCode = GetLastError();
            //    errorMessage = ("LookupAccountName failed: " + winErrorCode);
            //}
            // else
            //{
            LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();

            IntPtr policyHandle = IntPtr.Zero;
            IntPtr userRightsPtr = IntPtr.Zero;
            int countOfRights = 0;

            LSA_OBJECT_ATTRIBUTES objectAttributes = CreateLSAObject();

            uint policyStatus = LsaOpenPolicy(ref systemName, ref objectAttributes, Access, out policyHandle);
            winErrorCode = LsaNtStatusToWinError(policyStatus);
            if (winErrorCode != 0)
            {
                errorMessage = string.Format("OpenPolicy failed: {0}.", winErrorCode);
                throw new ApplicationException(string.Format("Error occured in LSA, error code {0}, detail: {1}", winErrorCode, errorMessage));
            }
            else
            {
                uint result = LsaEnumerateAccountRights(policyHandle, pSid, out userRightsPtr, out countOfRights);
                winErrorCode = LsaNtStatusToWinError(result);
                if (winErrorCode != 0)
                {
                    switch (winErrorCode)
                    {
                        case 2:
                            errorMessage = string.Format("No directly assigned privilege for account {0}. (2)", accountName);
                            break;
                        case 1332:
                            errorMessage = string.Format("Cannot find SID for account {0}. (1332)", accountName);
                            break;
                        default:
                            errorMessage = string.Format("LsaEnumerateAccountRights failed: {0}", winErrorCode);
                            break;
                    }
                    throw new ApplicationException(string.Format("Error occured in LSA, error code {0}, detail: {1}", winErrorCode, errorMessage));
                }
                else
                {
                    Int64 ptr = userRightsPtr.ToInt64();
                    LSA_UNICODE_STRING userRight;

                    for (int i = 0; i < countOfRights; i++)
                    {
                        userRight = (LSA_UNICODE_STRING)Marshal.PtrToStructure(new IntPtr(ptr), typeof(LSA_UNICODE_STRING));
                        string userRightStr = Marshal.PtrToStringAuto(userRight.Buffer);
                        rights.Add(userRightStr);
                        ptr += Marshal.SizeOf(userRight);
                    }
                }
            }
            ///FreeSid(sid);
            LsaClose(policyHandle);
            return rights;
        }

        // Lists account with a privilege
        public IList<string> GetAccountsWithRight(string privilegeName)
        {
            LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = InitLsaString(privilegeName);
            IntPtr enumerationBuffer = IntPtr.Zero;
            long countReturned = 0;
            IList<string> accountNames = new List<string>();
            long winErrorCode = 0;
            string errorMessage = string.Empty;
            string theAccountName = string.Empty;
            IntPtr sid = IntPtr.Zero;
            LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();
            IntPtr policyHandle = IntPtr.Zero;
            LSA_OBJECT_ATTRIBUTES objectAttributes = CreateLSAObject();

            uint resultPolicy = LsaOpenPolicy(ref systemName, ref objectAttributes, Access, out policyHandle);
            winErrorCode = LsaNtStatusToWinError(resultPolicy);

            if (winErrorCode != 0)
            {
                errorMessage = string.Format("OpenPolicy failed: {0} ", winErrorCode);
            }
            else
            {
                LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1];
                uint res = LsaEnumerateAccountsWithUserRight(policyHandle, privileges, out enumerationBuffer, out countReturned);
                winErrorCode = LsaNtStatusToWinError(res);
                if (winErrorCode != 0)
                {
                    errorMessage = string.Format("LsaEnumerateAccountsWithUserRight failed: {0}", winErrorCode);
                }
                LsaClose(policyHandle);
            }

            if (winErrorCode > 0)
            {
                switch (winErrorCode)
                {
                    case 1313:
                        errorMessage = "Specified privilege does not exist. (1313)";
                        break;
                    case 259:
                        errorMessage = "No accounts found. (259)";
                        break;
                    default:
                        ;
                        break;
                }
                throw new ApplicationException(string.Format("Failed to enumerate accounts - Error: {0}", errorMessage));
            }
            else
            {
                LSA_ENUMERATION_INFORMATION[] LsaInfo = new LSA_ENUMERATION_INFORMATION[countReturned];
                for (long i = 0, elemOffs = (Int64)enumerationBuffer; i < countReturned; i++)
                {
                    LsaInfo[i] = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                     (IntPtr)elemOffs, typeof(LSA_ENUMERATION_INFORMATION));
                    elemOffs += Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION));
                }
                // Do something with LsaInfo here
                for (long i = 0; i < countReturned; i++)
                {
                    try
                    {
                        theAccountName = (new SecurityIdentifier(LsaInfo[i].PSid)).Translate(typeof(NTAccount)).ToString();
                    }
                    catch (System.Security.Principal.IdentityNotMappedException)
                    {
                        theAccountName = (new SecurityIdentifier(LsaInfo[i].PSid)).ToString();
                    }
                    accountNames.Add(theAccountName);
                }
                return accountNames;
            }
        }


        // Adds a privilege to an account
        public void SetRight(string accountName, string privilegeName)
        {
            long winErrorCode = 0;
            string errorMessage = string.Empty;
            IntPtr sid = IntPtr.Zero;
            int sidSize = 0;
            StringBuilder domainName = new StringBuilder();
            int nameSize = 0;
            int accountType = 0;

            LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);

            domainName = new StringBuilder(nameSize);
            sid = Marshal.AllocHGlobal(sidSize);

            if (!LookupAccountName(string.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType))
            {
                winErrorCode = GetLastError();
                errorMessage = string.Format("LookupAccountName failed: {0}", winErrorCode);
            }
            else
            {
                LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();
                IntPtr policyHandle = IntPtr.Zero;
                LSA_OBJECT_ATTRIBUTES objectAttributes = CreateLSAObject();

                uint resultPolicy = LsaOpenPolicy(ref systemName, ref objectAttributes, Access, out policyHandle);
                winErrorCode = LsaNtStatusToWinError(resultPolicy);

                if (winErrorCode != 0)
                {
                    errorMessage = string.Format("OpenPolicy failed: {0} ", winErrorCode);
                }
                else
                {
                    LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1];
                    userRights[0] = new LSA_UNICODE_STRING();
                    userRights[0].Buffer = Marshal.StringToHGlobalUni(privilegeName);
                    userRights[0].Length = (UInt16)(privilegeName.Length * UnicodeEncoding.CharSize);
                    userRights[0].MaximumLength = (UInt16)((privilegeName.Length + 1) * UnicodeEncoding.CharSize);

                    uint res = LsaAddAccountRights(policyHandle, sid, userRights, 1);
                    winErrorCode = LsaNtStatusToWinError(res);
                    if (winErrorCode != 0)
                    {
                        errorMessage = string.Format("LsaAddAccountRights failed: {0}", winErrorCode);
                    }

                    LsaClose(policyHandle);
                }
                FreeSid(sid);
            }

            if (winErrorCode > 0)
            {
                throw new ApplicationException(string.Format("Failed to add right {0} to {1}. Error detail:{2}", accountName, privilegeName, errorMessage));
            }
        }

        // Remove a privilege from an account
        public void RemoveRight(string accountName, string privilegeName)
        {
            long winErrorCode = 0;
            string errorMessage = string.Empty;
            IntPtr sid = IntPtr.Zero;
            int sidSize = 0;
            StringBuilder domainName = new StringBuilder();
            int nameSize = 0;
            int accountType = 0;

            LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);

            domainName = new StringBuilder(nameSize);
            sid = Marshal.AllocHGlobal(sidSize);

            if (!LookupAccountName(string.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType))
            {
                winErrorCode = GetLastError();
                errorMessage = string.Format("LookupAccountName failed: {0}", winErrorCode);
            }
            else
            {
                LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();
                IntPtr policyHandle = IntPtr.Zero;
                LSA_OBJECT_ATTRIBUTES objectAttributes = CreateLSAObject();

                uint resultPolicy = LsaOpenPolicy(ref systemName, ref objectAttributes, Access, out policyHandle);
                winErrorCode = LsaNtStatusToWinError(resultPolicy);

                if (winErrorCode != 0)
                {
                    errorMessage = string.Format("OpenPolicy failed: {0} ", winErrorCode);
                }
                else
                {
                    LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1];
                    userRights[0] = new LSA_UNICODE_STRING();
                    userRights[0].Buffer = Marshal.StringToHGlobalUni(privilegeName);
                    userRights[0].Length = (UInt16)(privilegeName.Length * UnicodeEncoding.CharSize);
                    userRights[0].MaximumLength = (UInt16)((privilegeName.Length + 1) * UnicodeEncoding.CharSize);
                    /// Only one right, to make it simple.
                    uint res = LsaRemoveAccountRights(policyHandle, sid, false, userRights, 1);
                    winErrorCode = LsaNtStatusToWinError(res);
                    if (winErrorCode != 0)
                    {
                        errorMessage = string.Format("LsaRemoveAccountRights failed: {0}", winErrorCode);
                    }
                    LsaClose(policyHandle);
                }
                FreeSid(sid);
            }

            if (winErrorCode > 0)
            {
                throw new ApplicationException(string.Format("Failed to remove right {0} from {1}. Error detail:{2}", accountName, privilegeName, errorMessage));
            }
        }

        public void SetRights(string accountName, IList<string> rights)
        {
            rights.ToList().ForEach(right => SetRight(accountName, right));
        }

        public void RemoveRights(string accountName, IList<string> rights)
        {
            rights.ToList().ForEach(right => RemoveRight(accountName, right));
        }


        private static LSA_OBJECT_ATTRIBUTES CreateLSAObject()
        {
            LSA_OBJECT_ATTRIBUTES newInstance = new LSA_OBJECT_ATTRIBUTES();

            newInstance.Length = 0;
            newInstance.RootDirectory = IntPtr.Zero;
            newInstance.Attributes = 0;
            newInstance.SecurityDescriptor = IntPtr.Zero;
            newInstance.SecurityQualityOfService = IntPtr.Zero;

            return newInstance;
        }

        static LSA_UNICODE_STRING InitLsaString(string lsaString)
        {
            // Unicode strings max. 32KB
            if (lsaString.Length > 0x7ffe)
                throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = Marshal.StringToHGlobalUni(lsaString);
            lus.Length = (ushort)(lsaString.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }
}