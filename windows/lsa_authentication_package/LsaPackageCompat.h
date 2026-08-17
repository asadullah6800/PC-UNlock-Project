#pragma once

// ============================================================
// LsaPackageCompat.h — Windows LSA Authentication Package SDK
// compatibility header for MinGW / cross-compiler builds.
//
// Defines only the types, constants, structs, and function
// signatures required by the MobileFingerprintUnlock LSA Package
// (Phase 8).
//
// Reference: Windows SDK ntsecpkg.h, ntsecapi.h, subauth.h
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#ifndef NTAPI
#define NTAPI __stdcall
#endif

// ============================================================
// NTSTATUS codes required by LSA Authentication Packages
// ============================================================
#ifndef _NTSTATUS_
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#define _NTSTATUS_
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE            ((NTSTATUS)0xC000006DL)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION      ((NTSTATUS)0xC000006EL)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_NO_SUCH_USER
#define STATUS_NO_SUCH_USER             ((NTSTATUS)0xC0000064L)
#endif
#ifndef STATUS_ACCOUNT_DISABLED
#define STATUS_ACCOUNT_DISABLED         ((NTSTATUS)0xC0000072L)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_ACCOUNT_EXPIRED
#define STATUS_ACCOUNT_EXPIRED          ((NTSTATUS)0xC0000193L)
#endif

// ============================================================
// LSA String Structures
// ============================================================
#ifndef _LSA_STRING_DEFINED
#define _LSA_STRING_DEFINED
typedef struct _LSA_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} LSA_STRING, *PLSA_STRING;
#endif

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

// ============================================================
// SECURITY_LOGON_TYPE
// ============================================================
#ifndef _SECURITY_LOGON_TYPE_DEFINED
#define _SECURITY_LOGON_TYPE_DEFINED
typedef enum _SECURITY_LOGON_TYPE {
    UndefinedLogonType       = 0,
    Interactive              = 2,
    Network                  = 3,
    Batch                    = 4,
    Service                  = 5,
    Proxy                    = 6,
    Unlock                   = 7,
    NetworkCleartext         = 8,
    NewCredentials           = 9,
    RemoteInteractive        = 10,
    CachedInteractive        = 11,
    CachedRemoteInteractive  = 12,
    CachedUnlock             = 13
} SECURITY_LOGON_TYPE, *PSECURITY_LOGON_TYPE;
#endif

// ============================================================
// LSA Client Request & LUID
// ============================================================
typedef struct _LSA_CLIENT_REQUEST *PLSA_CLIENT_REQUEST;

// ============================================================
// LSA Token Information Structures
// ============================================================
typedef enum _LSA_TOKEN_INFORMATION_TYPE {
    LsaTokenInformationNull = 0,
    LsaTokenInformationV1   = 1,
    LsaTokenInformationV2   = 2,
    LsaTokenInformationV3   = 3
} LSA_TOKEN_INFORMATION_TYPE, *PLSA_TOKEN_INFORMATION_TYPE;

typedef struct _LSA_TOKEN_INFORMATION_V2 {
    LARGE_INTEGER ExpirationTime;
    TOKEN_USER User;
    PTOKEN_GROUPS Groups;
    PTOKEN_PRIVILEGES Privileges;
    PTOKEN_OWNER Owner;
    PTOKEN_PRIMARY_GROUP PrimaryGroup;
    PTOKEN_DEFAULT_DACL DefaultDacl;
} LSA_TOKEN_INFORMATION_V2, *PLSA_TOKEN_INFORMATION_V2;

// ============================================================
// Credentials Structures
// ============================================================
typedef struct _SECPKG_PRIMARY_CRED {
    LUID LogonId;
    LSA_STRING PackageName;
    LSA_STRING Domain;
    LSA_STRING DownlevelName;
    LSA_STRING Upn;
    LSA_STRING UserSid;
    ULONG Flags;
    UNICODE_STRING Password;
} SECPKG_PRIMARY_CRED, *PSECPKG_PRIMARY_CRED;

typedef struct _SECPKG_SUPPLEMENTAL_CRED {
    LSA_STRING PackageName;
    ULONG CredentialLength;
    PUCHAR Credentials;
} SECPKG_SUPPLEMENTAL_CRED, *PSECPKG_SUPPLEMENTAL_CRED;

typedef struct _SECPKG_SUPPLEMENTAL_CRED_ARRAY {
    ULONG CredentialCount;
    SECPKG_SUPPLEMENTAL_CRED Credentials[ANYSIZE_ARRAY];
} SECPKG_SUPPLEMENTAL_CRED_ARRAY, *PSECPKG_SUPPLEMENTAL_CRED_ARRAY;

// ============================================================
// LSA Dispatch Table (Helper Function Pointers)
// ============================================================
typedef PVOID (NTAPI *PLSA_ALLOCATE_LSA_HEAP)(ULONG Length);
typedef VOID  (NTAPI *PLSA_FREE_LSA_HEAP)(PVOID Base);

typedef NTSTATUS (NTAPI *PLSA_ALLOCATE_CLIENT_BUFFER)(
    PLSA_CLIENT_REQUEST ClientRequest,
    ULONG Length,
    PVOID *ClientBase
);

typedef NTSTATUS (NTAPI *PLSA_FREE_CLIENT_BUFFER)(
    PLSA_CLIENT_REQUEST ClientRequest,
    PVOID ClientBase
);

typedef NTSTATUS (NTAPI *PLSA_COPY_TO_CLIENT_BUFFER)(
    PLSA_CLIENT_REQUEST ClientRequest,
    ULONG Length,
    PVOID ClientBase,
    PVOID Buffer
);

typedef NTSTATUS (NTAPI *PLSA_COPY_FROM_CLIENT_BUFFER)(
    PLSA_CLIENT_REQUEST ClientRequest,
    ULONG Length,
    PVOID Buffer,
    PVOID ClientBase
);

typedef struct _LSA_DISPATCH_TABLE {
    PLSA_ALLOCATE_LSA_HEAP       AllocateLsaHeap;
    PLSA_FREE_LSA_HEAP           FreeLsaHeap;
    PLSA_ALLOCATE_CLIENT_BUFFER  AllocateClientBuffer;
    PLSA_FREE_CLIENT_BUFFER      FreeClientBuffer;
    PLSA_COPY_TO_CLIENT_BUFFER   CopyToClientBuffer;
    PLSA_COPY_FROM_CLIENT_BUFFER CopyFromClientBuffer;
} LSA_DISPATCH_TABLE, *PLSA_DISPATCH_TABLE;
