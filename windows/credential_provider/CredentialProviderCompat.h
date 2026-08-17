#pragma once

// ============================================================
// CredentialProviderCompat.h — Minimal Windows Credential Provider
// compatibility header for MinGW / cross-compiler builds.
//
// Defines only the types, constants, and interfaces required
// by the MobileFingerprintUnlock Credential Provider (Phase 7).
//
// On MSVC / Windows SDK builds, this provides standard SDK types.
// ============================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <unknwn.h>
#include <objbase.h>

#ifndef _NTSTATUS_
typedef LONG NTSTATUS;
#define _NTSTATUS_
#endif

#ifndef SecureZeroMemory
#define SecureZeroMemory(p, s) do { volatile char* _p = (volatile char*)(p); size_t _s = (size_t)(s); while (_s--) *_p++ = 0; } while(0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef MIDL_INTERFACE
#define MIDL_INTERFACE(x) struct __declspec(uuid(x)) __declspec(novtable)
#endif

#ifndef IFACEMETHODIMP
#define IFACEMETHODIMP HRESULT STDMETHODCALLTYPE
#endif
#ifndef IFACEMETHODIMP_
#define IFACEMETHODIMP_(type) type STDMETHODCALLTYPE
#endif

// ============================================================
// CREDENTIAL_PROVIDER_USAGE_SCENARIO
// ============================================================
typedef enum _CREDENTIAL_PROVIDER_USAGE_SCENARIO {
    CPUS_INVALID                = 0,
    CPUS_LOGON                  = 1,
    CPUS_UNLOCK_WORKSTATION     = 2,
    CPUS_CHANGE_PASSWORD        = 3,
    CPUS_CREDUI                 = 4,
    CPUS_PLAP                   = 5,
} CREDENTIAL_PROVIDER_USAGE_SCENARIO;

// ============================================================
// CREDENTIAL_PROVIDER_FIELD_TYPE
// ============================================================
typedef enum _CREDENTIAL_PROVIDER_FIELD_TYPE {
    CPFT_INVALID            = 0,
    CPFT_LARGE_TEXT         = 1,
    CPFT_SMALL_TEXT         = 2,
    CPFT_COMMAND_LINK       = 3,
    CPFT_EDIT_TEXT          = 4,
    CPFT_PASSWORD_TEXT      = 5,
    CPFT_TILE_IMAGE         = 6,
    CPFT_CHECKBOX           = 7,
    CPFT_COMBOBOX           = 8,
    CPFT_SUBMIT_BUTTON      = 9,
} CREDENTIAL_PROVIDER_FIELD_TYPE;

// ============================================================
// CREDENTIAL_PROVIDER_FIELD_STATE
// ============================================================
typedef enum _CREDENTIAL_PROVIDER_FIELD_STATE {
    CPFS_HIDDEN                                 = 0,
    CPFS_DISPLAY_IN_SELECTED_TILE               = 1,
    CPFS_DISPLAY_IN_DESELECTED_TILE             = 2,
    CPFS_DISPLAY_IN_BOTH                        = 3,
} CREDENTIAL_PROVIDER_FIELD_STATE;

// ============================================================
// CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE
// ============================================================
typedef enum _CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE {
    CPFIS_NONE      = 0,
    CPFIS_READONLY  = 1,
    CPFIS_DISABLED  = 2,
    CPFIS_FOCUSED   = 3,
} CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE;

// ============================================================
// CREDENTIAL_PROVIDER_STATUS_ICON
// ============================================================
typedef enum _CREDENTIAL_PROVIDER_STATUS_ICON {
    CPSI_NONE       = 0,
    CPSI_ERROR      = 1,
    CPSI_WARNING    = 2,
    CPSI_SUCCESS    = 3,
} CREDENTIAL_PROVIDER_STATUS_ICON;

// ============================================================
// CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE
// ============================================================
typedef enum _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE {
    CPGSR_NO_CREDENTIAL_NOT_FINISHED  = 0,
    CPGSR_NO_CREDENTIAL_FINISHED      = 1,
    CPGSR_RETURN_CREDENTIAL_FINISHED  = 2,
    CPGSR_RETURN_NO_CREDENTIAL_FINISHED = 3,
} CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE;

// ============================================================
// Well-known field GUIDs (subset used by our provider)
// ============================================================
// {DA15BBE8-954D-4fd3-B0F4-1FB5B90B174B}
#ifndef DECLSPEC_SELECTANY
#define DECLSPEC_SELECTANY __declspec(selectany)
#endif

EXTERN_C const GUID DECLSPEC_SELECTANY CPFG_CREDENTIAL_PROVIDER_LABEL =
    { 0xda15bbe8, 0x954d, 0x4fd3, { 0xb0, 0xf4, 0x1f, 0xb5, 0xb9, 0x0b, 0x17, 0x4b } };

// {2D4D3D8E-C62B-4c09-A285-4DC4859DD573}
EXTERN_C const GUID DECLSPEC_SELECTANY CPFG_CREDENTIAL_PROVIDER_LOGO =
    { 0x2d4d3d8e, 0xc62b, 0x4c09, { 0xa2, 0x85, 0x4d, 0xc4, 0x85, 0x9d, 0xd5, 0x73 } };

// ============================================================
// CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
// ============================================================
typedef struct _CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
    DWORD                          dwFieldID;
    CREDENTIAL_PROVIDER_FIELD_TYPE cpft;
    LPWSTR                         pszLabel;
    GUID                           guidFieldType;
} CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;

// ============================================================
// CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION
// ============================================================
typedef struct _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
    ULONG  ulAuthenticationPackage;
    GUID   clsidCredentialProvider;
    ULONG  cbSerialization;
    BYTE*  rgbSerialization;
} CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION;

// Sentinel for "no default credential"
#ifndef CREDENTIAL_PROVIDER_NO_DEFAULT
#define CREDENTIAL_PROVIDER_NO_DEFAULT  ((DWORD)-1)
#endif

// ============================================================
// IID declarations
// ============================================================
// {d545db01-e522-4a63-af83-d8ddf954004d}
EXTERN_C const GUID DECLSPEC_SELECTANY IID_ICredentialProvider =
    { 0xd545db01, 0xe522, 0x4a63, { 0xaf, 0x83, 0xd8, 0xdd, 0xf9, 0x54, 0x00, 0x4d } };

// {fd672c54-40ea-4d6e-9b0a-e3b4f9c3b236}
EXTERN_C const GUID DECLSPEC_SELECTANY IID_ICredentialProviderCredential =
    { 0xfd672c54, 0x40ea, 0x4d6e, { 0x9b, 0x0a, 0xe3, 0xb4, 0xf9, 0xc3, 0xb2, 0x36 } };

// {b5a5c3c0-d659-4f64-9ed0-8b8a35464224}
EXTERN_C const GUID DECLSPEC_SELECTANY IID_ICredentialProviderCredentialEvents =
    { 0xb5a5c3c0, 0xd659, 0x4f64, { 0x9e, 0xd0, 0x8b, 0x8a, 0x35, 0x46, 0x42, 0x24 } };

// ============================================================
// Forward declarations
// ============================================================
struct ICredentialProvider;
struct ICredentialProviderCredential;
struct ICredentialProviderCredentialEvents;
struct ICredentialProviderEvents;

// ============================================================
// ICredentialProviderCredentialEvents
// ============================================================
MIDL_INTERFACE("b5a5c3c0-d659-4f64-9ed0-8b8a35464224")
ICredentialProviderCredentialEvents : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE SetFieldState(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE cpfs) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetFieldInteractiveState(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetFieldString(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        PCWSTR psz) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetFieldCheckbox(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        BOOL bChecked,
        PCWSTR pszLabel) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetFieldBitmap(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        HBITMAP hbmp) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetFieldComboBoxSelectedItem(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        DWORD dwSelectedItem) = 0;

    virtual HRESULT STDMETHODCALLTYPE DeleteFieldComboBoxItem(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        DWORD dwItem) = 0;

    virtual HRESULT STDMETHODCALLTYPE AppendFieldComboBoxItem(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        PCWSTR pszItem) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetFieldSubmitButton(
        ICredentialProviderCredential* pcpc,
        DWORD dwFieldID,
        DWORD dwAdjacentTo) = 0;

    virtual HRESULT STDMETHODCALLTYPE OnCreatingWindow(HWND* phwndOwner) = 0;
};

// ============================================================
// ICredentialProviderCredential
// ============================================================
MIDL_INTERFACE("fd672c54-40ea-4d6e-9b0a-e3b8f9c3b236")
ICredentialProviderCredential : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE Advise(
        ICredentialProviderCredentialEvents* pcpce) = 0;

    virtual HRESULT STDMETHODCALLTYPE UnAdvise() = 0;

    virtual HRESULT STDMETHODCALLTYPE SetSelected(BOOL* pbAutoLogonWithDefault) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetDeselected() = 0;

    virtual HRESULT STDMETHODCALLTYPE GetFieldState(
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetStringValue(
        DWORD dwFieldID,
        PWSTR* ppwsz) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetBitmapValue(
        DWORD dwFieldID,
        HBITMAP* phbmp) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetCheckboxValue(
        DWORD dwFieldID,
        BOOL* pbChecked,
        PWSTR* ppwszLabel) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(
        DWORD dwFieldID,
        DWORD* pcItems,
        DWORD* pdwSelectedItem) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(
        DWORD dwFieldID,
        DWORD dwItem,
        PWSTR* ppwszItem) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(
        DWORD dwFieldID,
        DWORD* pdwAdjacentTo) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetStringValue(
        DWORD dwFieldID,
        PCWSTR pwz) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetCheckboxValue(
        DWORD dwFieldID,
        BOOL bChecked) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(
        DWORD dwFieldID,
        DWORD dwSelectedItem) = 0;

    virtual HRESULT STDMETHODCALLTYPE CommandLinkClicked(DWORD dwFieldID) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) = 0;

    virtual HRESULT STDMETHODCALLTYPE ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) = 0;
};

// ============================================================
// ICredentialProvider
// ============================================================
MIDL_INTERFACE("d545db01-e522-4a63-af83-d8ddf954004d")
ICredentialProvider : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE SetUsageScenario(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) = 0;

    virtual HRESULT STDMETHODCALLTYPE Advise(
        ICredentialProviderEvents* pcpe,
        UINT_PTR upAdviseContext) = 0;

    virtual HRESULT STDMETHODCALLTYPE UnAdvise() = 0;

    virtual HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(
        DWORD* pdwCount) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(
        DWORD dwIndex,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetCredentialCount(
        DWORD* pdwCount,
        DWORD* pdwDefault,
        BOOL* pbAutoLogonWithDefault) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetCredentialAt(
        DWORD dwIndex,
        ICredentialProviderCredential** ppcpc) = 0;
};

// ICredentialProviderEvents — minimal stub
MIDL_INTERFACE("2bd3b559-e2e4-4176-ab4c-1dcc03fc5f0f")
ICredentialProviderEvents : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE CredentialsChanged(UINT_PTR upAdviseContext) = 0;
};
