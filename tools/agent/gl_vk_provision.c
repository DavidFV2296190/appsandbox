#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <d3dkmthk.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <aclapi.h>
#pragma warning(pop)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "gl_vk_provision.h"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")

BOOL gpu_prefers_system_opengl(void)
{
#if defined(_M_X64)
    HMODULE gdi = LoadLibraryW(L"gdi32.dll");
    PFND3DKMT_ENUMADAPTERS2 enumerate;
    PFND3DKMT_QUERYADAPTERINFO query;
    PFND3DKMT_CLOSEADAPTER close;
    D3DKMT_ADAPTERINFO *adapters = NULL;
    D3DKMT_ENUMADAPTERS2 list = { 0 };
    ULONG i, capacity = 0;
    BOOL found = FALSE;

    if (!gdi) return FALSE;
    enumerate = (PFND3DKMT_ENUMADAPTERS2)GetProcAddress(gdi, "D3DKMTEnumAdapters2");
    query = (PFND3DKMT_QUERYADAPTERINFO)GetProcAddress(gdi, "D3DKMTQueryAdapterInfo");
    close = (PFND3DKMT_CLOSEADAPTER)GetProcAddress(gdi, "D3DKMTCloseAdapter");
    if (!enumerate || !query || !close || enumerate(&list) < 0 ||
        !list.NumAdapters) goto done;
    capacity = list.NumAdapters;
    adapters = calloc(capacity, sizeof(*adapters));
    if (!adapters) goto done;
    list.pAdapters = adapters;
    if (enumerate(&list) < 0 || list.NumAdapters > capacity) goto cleanup;
    for (i = 0; i < list.NumAdapters; i++) {
        D3DKMT_QUERY_DEVICE_IDS ids = { 0 };
        D3DKMT_ADAPTERTYPE type = { 0 };
        D3DKMT_QUERYADAPTERINFO info = { adapters[i].hAdapter,
            KMTQAITYPE_PHYSICALADAPTERDEVICEIDS, &ids, sizeof(ids) };

        if (query(&info) < 0 || (ids.DeviceIds.VendorID != 0x1002 &&
                                ids.DeviceIds.VendorID != 0x8086)) continue;
        info.Type = KMTQAITYPE_ADAPTERTYPE_RENDER;
        info.pPrivateDriverData = &type;
        info.PrivateDriverDataSize = sizeof(type);
        if (query(&info) >= 0 && type.Paravirtualized) {
            found = TRUE;
            break;
        }
    }
cleanup:
    for (i = 0; i < capacity; i++) {
        if (adapters[i].hAdapter) {
            D3DKMT_CLOSEADAPTER closing = { adapters[i].hAdapter };
            close(&closing);
        }
    }
done:
    free(adapters);
    FreeLibrary(gdi);
    return found;
#else
    return FALSE;
#endif
}

static BOOL files_equal(const wchar_t *a, const wchar_t *b)
{
    HANDLE fa, fb;
    LARGE_INTEGER sa, sb;
    BYTE ba[16384], bb[16384];
    DWORD na, nb;
    BOOL equal = FALSE;

    fa = CreateFileW(a, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    fb = CreateFileW(b, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fa == INVALID_HANDLE_VALUE || fb == INVALID_HANDLE_VALUE) goto done;
    if (!GetFileSizeEx(fa, &sa) || !GetFileSizeEx(fb, &sb) ||
        sa.QuadPart != sb.QuadPart) goto done;
    do {
        if (!ReadFile(fa, ba, sizeof(ba), &na, NULL) ||
            !ReadFile(fb, bb, sizeof(bb), &nb, NULL) ||
            na != nb || memcmp(ba, bb, na)) goto done;
    } while (na);
    equal = TRUE;
done:
    if (fa != INVALID_HANDLE_VALUE) CloseHandle(fa);
    if (fb != INVALID_HANDLE_VALUE) CloseHandle(fb);
    return equal;
}

static BOOL replace_file(const wchar_t *src, const wchar_t *dst)
{
    wchar_t folder[MAX_PATH], staged[MAX_PATH], previous[MAX_PATH], *slash;
    BOOL had_previous = FALSE, result = FALSE;
    DWORD error = ERROR_SUCCESS;

    if (files_equal(src, dst)) return TRUE;
    if (wcscpy_s(folder, MAX_PATH, dst)) return FALSE;
    slash = wcsrchr(folder, L'\\');
    if (!slash) return FALSE;
    *slash = 0;
    if (!GetTempFileNameW(folder, L"asb", 0, staged)) return FALSE;
    if (!CopyFileW(src, staged, FALSE) || !files_equal(src, staged)) goto done;
    if (GetFileAttributesW(dst) != INVALID_FILE_ATTRIBUTES) {
        if (!GetTempFileNameW(folder, L"asb", 0, previous)) goto done;
        DeleteFileW(previous);
        if (!MoveFileExW(dst, previous, MOVEFILE_WRITE_THROUGH)) goto done;
        had_previous = TRUE;
    }
    result = MoveFileExW(staged, dst, MOVEFILE_WRITE_THROUGH);
    error = GetLastError();
    if (!result && had_previous) {
        if (!MoveFileExW(previous, dst, MOVEFILE_WRITE_THROUGH))
            CopyFileW(previous, dst, TRUE);
        had_previous = FALSE;
    }
    if (result && had_previous && !DeleteFileW(previous))
        MoveFileExW(previous, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
done:
    if (!result && !error) error = GetLastError();
    DeleteFileW(staged);
    if (!result) SetLastError(error);
    return result;
}

static BOOL verify_microsoft_signature(WINTRUST_DATA *trust)
{
    static const GUID verify_policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    CRYPT_PROVIDER_DATA *provider;
    CRYPT_PROVIDER_SGNR *signer;
    wchar_t name[256];
    BOOL result = FALSE;

    trust->dwUIChoice = WTD_UI_NONE;
    trust->fdwRevocationChecks = WTD_REVOKE_NONE;
    trust->dwStateAction = WTD_STATEACTION_VERIFY;
    trust->dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    if (WinVerifyTrust(NULL, (GUID *)&verify_policy, trust) == ERROR_SUCCESS) {
        provider = WTHelperProvDataFromStateData(trust->hWVTStateData);
        signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : NULL;
        if (signer && signer->csCertChain &&
            CertGetNameStringW(signer->pasCertChain[0].pCert,
                               CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, 256))
            result = !_wcsicmp(name, L"Microsoft Windows") ||
                     !_wcsicmp(name, L"Microsoft Corporation");
    }
    trust->dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, (GUID *)&verify_policy, trust);
    return result;
}

static BOOL is_microsoft_opengl(const wchar_t *path)
{
    WINTRUST_FILE_INFO file = { sizeof(file) };
    WINTRUST_DATA trust = { sizeof(trust) };
    wchar_t query[96], *filename;
    struct { WORD language, codepage; } *translations;
    BYTE *version;
    DWORD size, unused;
    UINT length, count, i;
    BOOL result = FALSE;

    size = GetFileVersionInfoSizeW(path, &unused);
    if (!size || size > 1024 * 1024) return FALSE;
    version = malloc(size);
    if (!version) return FALSE;
    if (GetFileVersionInfoW(path, 0, size, version) &&
        VerQueryValueW(version, L"\\VarFileInfo\\Translation",
                       (void **)&translations, &length)) {
        count = length / sizeof(*translations);
        for (i = 0; i < count; i++) {
            swprintf_s(query, 96, L"\\StringFileInfo\\%04x%04x\\OriginalFilename",
                       translations[i].language, translations[i].codepage);
            if (VerQueryValueW(version, query, (void **)&filename, &length) &&
                length && (!_wcsicmp(filename, L"opengl32.dll") ||
                           !_wcsicmp(filename, L"opengl32"))) result = TRUE;
        }
    }
    free(version);
    if (!result) return FALSE;
    file.pcwszFilePath = path;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file;
    if (verify_microsoft_signature(&trust)) return TRUE;
    {
        const wchar_t *algorithms[] = { L"SHA256", L"SHA1" };
        HANDLE input = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        UINT algorithm;
        if (input == INVALID_HANDLE_VALUE) return FALSE;
        result = FALSE;
        for (algorithm = 0; algorithm < 2 && !result; algorithm++) {
            HCATADMIN admin;
            HCATINFO catalog = NULL;
            BYTE hash[64];
            DWORD hash_size = sizeof(hash);
            wchar_t tag[129];
            if (!CryptCATAdminAcquireContext2(&admin, NULL, algorithms[algorithm], NULL, 0))
                continue;
            SetFilePointer(input, 0, NULL, FILE_BEGIN);
            if (CryptCATAdminCalcHashFromFileHandle2(admin, input, &hash_size, hash, 0) &&
                hash_size <= sizeof(hash)) {
                for (i = 0; i < hash_size; i++)
                    swprintf_s(tag + i * 2, 129 - i * 2, L"%02X", hash[i]);
                while ((catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, hash_size,
                                                                   0, &catalog)) != NULL) {
                    CATALOG_INFO info = { sizeof(info) };
                    WINTRUST_CATALOG_INFO member = { sizeof(member) };
                    if (!CryptCATCatalogInfoFromContext(catalog, &info, 0)) continue;
                    member.pcwszCatalogFilePath = info.wszCatalogFile;
                    member.pcwszMemberTag = tag;
                    member.pcwszMemberFilePath = path;
                    member.hMemberFile = input;
                    member.pbCalculatedFileHash = hash;
                    member.cbCalculatedFileHash = hash_size;
                    member.hCatAdmin = admin;
                    ZeroMemory(&trust, sizeof(trust));
                    trust.cbStruct = sizeof(trust);
                    trust.dwUnionChoice = WTD_CHOICE_CATALOG;
                    trust.pCatalog = &member;
                    if (verify_microsoft_signature(&trust)) {
                        result = TRUE;
                        CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                        break;
                    }
                }
            }
            CryptCATAdminReleaseContext(admin, 0);
        }
        CloseHandle(input);
    }
    return result;
}

static BOOL grant_system_file_control(const wchar_t *path)
{
    HANDLE token;
    TOKEN_PRIVILEGES privileges = { 1 };
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid), result;
    EXPLICIT_ACCESSW access = { 0 };
    PACL acl = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token)) return FALSE;
    if (!LookupPrivilegeValueW(NULL, SE_TAKE_OWNERSHIP_NAME,
                              &privileges.Privileges[0].Luid)) {
        CloseHandle(token);
        return FALSE;
    }
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL);
    CloseHandle(token);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &sid_size)) return FALSE;
    result = SetNamedSecurityInfoW((wchar_t *)path, SE_FILE_OBJECT,
                                  OWNER_SECURITY_INFORMATION, sid, NULL, NULL, NULL);
    if (result != ERROR_SUCCESS) return FALSE;
    access.grfAccessPermissions = GENERIC_ALL;
    access.grfAccessMode = GRANT_ACCESS;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = (wchar_t *)sid;
    {
        PACL old_acl = NULL;
        PSECURITY_DESCRIPTOR descriptor = NULL;
        result = GetNamedSecurityInfoW((wchar_t *)path, SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION, NULL, NULL,
                                      &old_acl, NULL, &descriptor);
        if (result == ERROR_SUCCESS)
            result = SetEntriesInAclW(1, &access, old_acl, &acl);
        if (descriptor) LocalFree(descriptor);
    }
    if (result == ERROR_SUCCESS)
        result = SetNamedSecurityInfoW((wchar_t *)path, SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL);
    if (acl) LocalFree(acl);
    return result == ERROR_SUCCESS;
}

#if defined(_M_X64)
static BOOL validate_opengl_dll(const wchar_t *path, WORD machine, BOOL native)
{
    HMODULE module = LoadLibraryExW(path, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    BYTE *base;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_DATA_DIRECTORY directory;
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *names, i, size;
    BOOL found = FALSE;

    if (!module) return FALSE;
    base = (BYTE *)((ULONG_PTR)module & ~(ULONG_PTR)3);
    nt = (IMAGE_NT_HEADERS64 *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    if (nt->FileHeader.Machine != machine) goto done;
    if (machine == IMAGE_FILE_MACHINE_AMD64 &&
        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        size = nt->OptionalHeader.SizeOfImage;
        directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else if (machine == IMAGE_FILE_MACHINE_I386 &&
               nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32 *)nt;
        size = nt32->OptionalHeader.SizeOfImage;
        directory = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else goto done;
    if (!native) { found = TRUE; goto done; }
    if (!directory.VirtualAddress || size < sizeof(*exports) ||
        directory.VirtualAddress > size - sizeof(*exports)) goto done;
    exports = (IMAGE_EXPORT_DIRECTORY *)(base + directory.VirtualAddress);
    if (exports->NumberOfNames > size / sizeof(DWORD) ||
        exports->AddressOfNames > size - exports->NumberOfNames * sizeof(DWORD)) goto done;
    names = (DWORD *)(base + exports->AddressOfNames);
    for (i = 0; i < exports->NumberOfNames; i++) {
        if (names[i] <= size - sizeof("appsandbox_nvidia") &&
            !memcmp(base + names[i], "appsandbox_nvidia", sizeof("appsandbox_nvidia"))) {
            found = TRUE;
            break;
        }
    }
done:
    FreeLibrary(module);
    return found;
}

static UINT find_nvidia_vulkan_manifests(wchar_t paths[32][MAX_PATH], const wchar_t *sys,
                             const wchar_t *manifest)
{
    typedef NTSTATUS (APIENTRY *EnumAdaptersFn)(const D3DKMT_ENUMADAPTERS2 *);
    typedef NTSTATUS (APIENTRY *QueryAdapterFn)(const D3DKMT_QUERYADAPTERINFO *);
    typedef NTSTATUS (APIENTRY *CloseAdapterFn)(const D3DKMT_CLOSEADAPTER *);
    HMODULE gdi = LoadLibraryW(L"gdi32.dll");
    EnumAdaptersFn enumerate;
    QueryAdapterFn query;
    CloseAdapterFn close;
    D3DKMT_ADAPTERINFO *adapters = NULL;
    D3DKMT_ENUMADAPTERS2 list = { 0 };
    ULONG i, capacity = 0;
    UINT count = 0;

    if (!gdi) return 0;
    enumerate = (EnumAdaptersFn)GetProcAddress(gdi, "D3DKMTEnumAdapters2");
    query = (QueryAdapterFn)GetProcAddress(gdi, "D3DKMTQueryAdapterInfo");
    close = (CloseAdapterFn)GetProcAddress(gdi, "D3DKMTCloseAdapter");
    if (!enumerate || !query || !close || enumerate(&list) < 0 ||
        !list.NumAdapters) goto done;
    capacity = list.NumAdapters;
    adapters = calloc(capacity, sizeof(*adapters));
    if (!adapters) goto done;
    list.pAdapters = adapters;
    if (enumerate(&list) < 0 || list.NumAdapters > capacity) goto cleanup;
    for (i = 0; i < list.NumAdapters; i++) {
        D3DKMT_QUERY_DEVICE_IDS ids = { 0 };
        D3DKMT_ADAPTERTYPE type = { 0 };
        D3DKMT_OPENGLINFO gl = { 0 };
        D3DKMT_QUERYADAPTERINFO info = { adapters[i].hAdapter,
            KMTQAITYPE_PHYSICALADAPTERDEVICEIDS, &ids, sizeof(ids) };
        wchar_t driver[MAX_PATH], path[MAX_PATH], *slash, *store;
        UINT j;

        if (query(&info) < 0 || ids.DeviceIds.VendorID != 0x10de) goto next;
        info.Type = KMTQAITYPE_ADAPTERTYPE_RENDER;
        info.pPrivateDriverData = &type;
        info.PrivateDriverDataSize = sizeof(type);
        if (query(&info) < 0 || !type.Paravirtualized) goto next;
        info.Type = KMTQAITYPE_UMOPENGLINFO;
        info.pPrivateDriverData = &gl;
        info.PrivateDriverDataSize = sizeof(gl);
        if (query(&info) < 0 || !gl.UmdOpenGlIcdFileName[0]) goto next;
        gl.UmdOpenGlIcdFileName[MAX_PATH - 1] = 0;
        if (!_wcsnicmp(gl.UmdOpenGlIcdFileName, L"\\SystemRoot\\", 12)) {
            wchar_t windows[MAX_PATH];
            if (!GetWindowsDirectoryW(windows, MAX_PATH)) goto next;
            swprintf_s(driver, MAX_PATH, L"%s\\%s", windows, gl.UmdOpenGlIcdFileName + 12);
        } else if (!_wcsnicmp(gl.UmdOpenGlIcdFileName, L"\\??\\", 4)) {
            wcscpy_s(driver, MAX_PATH, gl.UmdOpenGlIcdFileName + 4);
        } else if (gl.UmdOpenGlIcdFileName[1] == L':') {
            wcscpy_s(driver, MAX_PATH, gl.UmdOpenGlIcdFileName);
        } else {
            swprintf_s(driver, MAX_PATH, L"%s\\%s", sys, gl.UmdOpenGlIcdFileName);
        }
        if (GetFileAttributesW(driver) == INVALID_FILE_ATTRIBUTES &&
            (store = wcsstr(driver, L"\\DriverStore\\")) != NULL) {
            wchar_t suffix[MAX_PATH];
            wcscpy_s(suffix, MAX_PATH, store + 12);
            *store = 0;
            wcscat_s(driver, MAX_PATH, L"\\HostDriverStore");
            wcscat_s(driver, MAX_PATH, suffix);
        }
        slash = wcsrchr(driver, L'\\');
        if (!slash || _wcsicmp(slash + 1, L"nvoglv64.dll") ||
            GetFileAttributesW(driver) == INVALID_FILE_ATTRIBUTES) goto next;
        *slash = 0;
        if (!_wcsicmp(manifest, L"nv-vk32.json")) {
            swprintf_s(path, MAX_PATH, L"%s\\nvoglv32.dll", driver);
            if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) goto next;
        }
        swprintf_s(path, MAX_PATH, L"%s\\%s", driver, manifest);
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) goto next;
        for (j = 0; j < count; j++)
            if (!_wcsicmp(paths[j], path)) break;
        if (j == count && count < 32) wcscpy_s(paths[count++], MAX_PATH, path);
next:
        ;
    }
cleanup:
    for (i = 0; i < capacity; i++) {
        if (adapters[i].hAdapter) {
            D3DKMT_CLOSEADAPTER closing = { adapters[i].hAdapter };
            close(&closing);
        }
    }
done:
    free(adapters);
    FreeLibrary(gdi);
    return count;
}

static const char *json_skip_whitespace(const char *p)
{
    while (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t') p++;
    return p;
}

static const char *json_skip_string(const char *p)
{
    if (*p++ != '"') return NULL;
    while (*p && *p != '"') {
        if ((unsigned char)*p < 32) return NULL;
        if (*p++ == '\\') {
            int i;
            if (!*p) return NULL;
            if (*p == 'u') {
                p++;
                for (i = 0; i < 4; i++, p++)
                    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
                          (*p >= 'A' && *p <= 'F'))) return NULL;
            } else if (strchr("\"\\/bfnrt", *p)) {
                p++;
            } else return NULL;
        }
    }
    return *p == '"' ? p + 1 : NULL;
}

static const char *json_skip_value(const char *p, int depth)
{
    char end;
    if (depth > 32) return NULL;
    p = json_skip_whitespace(p);
    if (*p == '"') return json_skip_string(p);
    if (*p == '{' || *p == '[') {
        BOOL object = *p == '{';
        end = object ? '}' : ']';
        p = json_skip_whitespace(p + 1);
        if (*p == end) return p + 1;
        for (;;) {
            if (object) {
                p = json_skip_string(p);
                if (!p || *(p = json_skip_whitespace(p)) != ':') return NULL;
                p++;
            }
            p = json_skip_value(p, depth + 1);
            if (!p) return NULL;
            p = json_skip_whitespace(p);
            if (*p == end) return p + 1;
            if (*p++ != ',') return NULL;
            p = json_skip_whitespace(p);
        }
    }
    if (!strncmp(p, "true", 4)) return p + 4;
    if (!strncmp(p, "false", 5)) return p + 5;
    if (!strncmp(p, "null", 4)) return p + 4;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else {
        if (*p < '1' || *p > '9') return NULL;
        while (*p >= '0' && *p <= '9') p++;
    }
    if (*p == '.') {
        p++;
        if (*p < '0' || *p > '9') return NULL;
        while (*p >= '0' && *p <= '9') p++;
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (*p < '0' || *p > '9') return NULL;
        while (*p >= '0' && *p <= '9') p++;
    }
    return p;
}

static const char *json_find_member(const char *p, const char *key)
{
    const char *name, *end, *found = NULL;
    size_t length = strlen(key);
    p = json_skip_whitespace(p);
    if (*p++ != '{') return NULL;
    p = json_skip_whitespace(p);
    while (*p && *p != '}') {
        name = p;
        end = json_skip_string(p);
        if (!end) return NULL;
        p = json_skip_whitespace(end);
        if (*p++ != ':') return NULL;
        p = json_skip_whitespace(p);
        if ((size_t)(end - name) == length + 2 && !memcmp(name + 1, key, length)) {
            if (found) return NULL;
            found = p;
        }
        p = json_skip_value(p, 0);
        if (!p) return NULL;
        p = json_skip_whitespace(p);
        if (*p == '}') break;
        if (*p++ != ',') return NULL;
        p = json_skip_whitespace(p);
    }
    return found;
}

static char *read_vulkan_manifest(const wchar_t *path, const char **library, const char **end)
{
    FILE *file;
    long length;
    char *text;
    const char *icd, *tail;
    if (_wfopen_s(&file, path, L"rb")) return NULL;
    if (fseek(file, 0, SEEK_END) || (length = ftell(file)) <= 0 || length > 65536 ||
        fseek(file, 0, SEEK_SET)) { fclose(file); return NULL; }
    text = calloc((size_t)length + 1, 1);
    if (!text) { fclose(file); return NULL; }
    if (fread(text, 1, length, file) != (size_t)length) {
        fclose(file); free(text); return NULL;
    }
    fclose(file);
    if (memchr(text, 0, length)) { free(text); return NULL; }
    tail = json_skip_value(text, 0);
    icd = json_find_member(text, "ICD");
    *library = icd ? json_find_member(icd, "library_path") : NULL;
    *end = *library ? json_skip_string(*library) : NULL;
    if (!tail || *json_skip_whitespace(tail) || !*library || !*end) {
        free(text);
        return NULL;
    }
    return text;
}

static BOOL update_vulkan_icd_path(const wchar_t *path, const wchar_t *runtime, BOOL restore)
{
    wchar_t backup[MAX_PATH], temporary[MAX_PATH], folder[MAX_PATH], *slash;
    char utf8[MAX_PATH * 4], escaped[MAX_PATH * 8 + 3];
    const char *library, *end;
    char *text;
    size_t i, n = 0;
    FILE *file;
    BOOL result = FALSE, ours;

    if (!WideCharToMultiByte(CP_UTF8, 0, runtime, -1, utf8, sizeof(utf8), NULL, NULL))
        return FALSE;
    escaped[n++] = '"';
    for (i = 0; utf8[i]; i++) {
        if (utf8[i] == '\\' || utf8[i] == '"') escaped[n++] = '\\';
        escaped[n++] = utf8[i];
    }
    escaped[n++] = '"';
    escaped[n] = 0;
    text = read_vulkan_manifest(path, &library, &end);
    if (!text) return FALSE;
    ours = (size_t)(end - library) == n && !memcmp(library, escaped, n);
    swprintf_s(backup, MAX_PATH, L"%s.asbak", path);
    if (restore || ours) {
        char *original;
        const char *old_library, *old_end;
        if (!ours) { free(text); return TRUE; }
        original = read_vulkan_manifest(backup, &old_library, &old_end);
        if (original) {
            BOOL valid = (size_t)(old_end - old_library) != n ||
                         memcmp(old_library, escaped, n);
            if (valid) result = !restore || replace_file(backup, path);
            free(original);
        }
        free(text);
        return result;
    }
    if (!replace_file(path, backup)) { free(text); return FALSE; }
    wcscpy_s(folder, MAX_PATH, path);
    slash = wcsrchr(folder, L'\\');
    if (!slash) { free(text); return FALSE; }
    *slash = 0;
    if (!GetTempFileNameW(folder, L"asb", 0, temporary)) { free(text); return FALSE; }
    if (!_wfopen_s(&file, temporary, L"wb")) {
        size_t prefix = (size_t)(library - text), suffix = strlen(end);
        result = fwrite(text, 1, prefix, file) == prefix &&
                 fwrite(escaped, 1, n, file) == n &&
                 fwrite(end, 1, suffix, file) == suffix;
        if (fclose(file)) result = FALSE;
        if (result) result = replace_file(temporary, path);
    }
    DeleteFileW(temporary);
    free(text);
    return result;
}

static BOOL restore_nvidia_vulkan_manifests(const wchar_t *sys, const wchar_t *runtime,
                              const wchar_t *manifest)
{
    const wchar_t *stores[] = { L"HostDriverStore", L"DriverStore" };
    WIN32_FIND_DATAW data;
    wchar_t pattern[MAX_PATH], path[MAX_PATH];
    HANDLE find;
    UINT i;
    BOOL result = TRUE;

    swprintf_s(path, MAX_PATH, L"%s\\%s.asbak", sys, manifest);
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        path[wcslen(path) - wcslen(L".asbak")] = 0;
        if (!update_vulkan_icd_path(path, runtime, TRUE)) result = FALSE;
    }
    for (i = 0; i < sizeof(stores) / sizeof(stores[0]); i++) {
        swprintf_s(pattern, MAX_PATH, L"%s\\%s\\FileRepository\\*", sys, stores[i]);
        find = FindFirstFileW(pattern, &data);
        if (find == INVALID_HANDLE_VALUE) {
            if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
                result = FALSE;
            continue;
        }
        do {
            if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || data.cFileName[0] == L'.')
                continue;
            swprintf_s(path, MAX_PATH, L"%s\\%s\\FileRepository\\%s\\%s.asbak",
                       sys, stores[i], data.cFileName, manifest);
            if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) continue;
            path[wcslen(path) - wcslen(L".asbak")] = 0;
            if (!update_vulkan_icd_path(path, runtime, TRUE)) result = FALSE;
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    return result;
}
#endif

static BOOL provision_gl_vk_for_arch(const wchar_t *dir, const wchar_t *native_dir,
                               const wchar_t *sys, const wchar_t *driver_sys,
                               WORD machine, BOOL system_runtime, BOOL *native_runtime)
{
    wchar_t runtime[MAX_PATH], backup[MAX_PATH], src[MAX_PATH], dst[MAX_PATH];
    BOOL microsoft;

    if (native_runtime) *native_runtime = FALSE;
    swprintf_s(runtime, MAX_PATH, L"%s\\opengl32.dll", sys);
    swprintf_s(backup, MAX_PATH, L"%s\\opengl32.dll.msbak", sys);
    microsoft = is_microsoft_opengl(runtime);
#if defined(_M_X64)
    if (microsoft && !validate_opengl_dll(runtime, machine, FALSE)) return FALSE;
#endif
    if (microsoft && !replace_file(runtime, backup)) return FALSE;
#if defined(_M_X64)
    {
        wchar_t manifests[32][MAX_PATH], backend[MAX_PATH], previous[MAX_PATH];
        const wchar_t *payload = machine == IMAGE_FILE_MACHINE_I386 ?
            L"AppSandbox-NVIDIA-VK-GL-shim32.dll" : L"AppSandbox-NVIDIA-VK-GL-shim.dll";
        const wchar_t *manifest = machine == IMAGE_FILE_MACHINE_I386 ?
            L"nv-vk32.json" : L"nv-vk64.json";
        UINT count = 0, i;
        src[0] = 0;
        if (native_dir && native_dir[0])
            swprintf_s(src, MAX_PATH, L"%s\\%s", native_dir, payload);
        if (src[0] && validate_opengl_dll(src, machine, TRUE) &&
            (count = find_nvidia_vulkan_manifests(manifests, driver_sys, manifest)) != 0 &&
            is_microsoft_opengl(backup) && validate_opengl_dll(backup, machine, FALSE)) {
            swprintf_s(backend, MAX_PATH, L"%s\\appsandbox-opengl32.dll", sys);
            if (replace_file(backup, backend) &&
                GetTempFileNameW(sys, L"asb", 0, previous)) {
                BOOL saved = CopyFileW(runtime, previous, FALSE);
                BOOL installed = saved &&
                    (files_equal(src, runtime) || grant_system_file_control(runtime)) &&
                    replace_file(src, runtime);
                if (installed) {
                    for (i = 0; i < count; i++)
                        if (!update_vulkan_icd_path(manifests[i], runtime, FALSE)) break;
                    if (i == count) {
                        DeleteFileW(previous);
                        if (native_runtime) *native_runtime = TRUE;
                        return TRUE;
                    }
                    {
                        BOOL manifests_restored = restore_nvidia_vulkan_manifests(driver_sys, runtime, manifest);
                        BOOL runtime_restored = replace_file(previous, runtime);
                        if (!runtime_restored) return FALSE;
                        if (!manifests_restored) {
                            DeleteFileW(previous);
                            return FALSE;
                        }
                    }
                }
                DeleteFileW(previous);
            }
        }
        if (!restore_nvidia_vulkan_manifests(driver_sys, runtime, manifest)) return FALSE;
        if (system_runtime) {
            BOOL installed = microsoft ||
                (is_microsoft_opengl(backup) && validate_opengl_dll(backup, machine, FALSE) &&
                 (GetFileAttributesW(runtime) == INVALID_FILE_ATTRIBUTES ||
                  grant_system_file_control(runtime)) && replace_file(backup, runtime));
            if (native_runtime) *native_runtime = installed;
            return installed;
        }
        if ((!dir || !dir[0]) && validate_opengl_dll(runtime, machine, TRUE)) {
            if (!is_microsoft_opengl(backup) || !validate_opengl_dll(backup, machine, FALSE) ||
                !grant_system_file_control(runtime) ||
                !replace_file(backup, runtime)) return FALSE;
        }
    }
#else
    (void)native_dir;
    (void)driver_sys;
    (void)machine;
    (void)system_runtime;
#endif
    if (!dir || !dir[0]) return machine == IMAGE_FILE_MACHINE_I386 && is_microsoft_opengl(runtime);
    swprintf_s(src, MAX_PATH, L"%s\\gallium_wgl.dll", dir);
    swprintf_s(dst, MAX_PATH, L"%s\\gallium_wgl.dll", sys);
    if (!replace_file(src, dst)) return FALSE;
    swprintf_s(src, MAX_PATH, L"%s\\z-1.dll", dir);
    swprintf_s(dst, MAX_PATH, L"%s\\z-1.dll", sys);
    if (!replace_file(src, dst)) return FALSE;
    swprintf_s(src, MAX_PATH, L"%s\\opengl32.dll", dir);
    if (files_equal(src, runtime)) return TRUE;
    if (GetFileAttributesW(backup) == INVALID_FILE_ATTRIBUTES && !microsoft) return FALSE;
    return (GetFileAttributesW(runtime) == INVALID_FILE_ATTRIBUTES ||
            grant_system_file_control(runtime)) && replace_file(src, runtime);
}

BOOL gl_vk_provision_runtime(const wchar_t *dir, const wchar_t *native_dir,
                             const wchar_t *sys, BOOL *native_runtime)
{
#if defined(_M_X64)
    wchar_t wow[MAX_PATH], payload[MAX_PATH], runtime[MAX_PATH];
    BOOL system_runtime = gpu_prefers_system_opengl();
    BOOL result = provision_gl_vk_for_arch(dir, native_dir, sys, sys, IMAGE_FILE_MACHINE_AMD64,
                                    system_runtime, native_runtime);
    if (GetSystemWow64DirectoryW(wow, MAX_PATH)) {
        payload[0] = 0;
        if (native_dir && native_dir[0])
            swprintf_s(payload, MAX_PATH, L"%s\\AppSandbox-NVIDIA-VK-GL-shim32.dll", native_dir);
        swprintf_s(runtime, MAX_PATH, L"%s\\opengl32.dll", wow);
        if (system_runtime ||
            (payload[0] && GetFileAttributesW(payload) != INVALID_FILE_ATTRIBUTES) ||
            validate_opengl_dll(runtime, IMAGE_FILE_MACHINE_I386, TRUE)) {
            if (!provision_gl_vk_for_arch(NULL, native_dir, wow, sys, IMAGE_FILE_MACHINE_I386,
                                    system_runtime, NULL))
                result = FALSE;
        }
    }
    return result;
#else
    return provision_gl_vk_for_arch(dir, native_dir, sys, sys, IMAGE_FILE_MACHINE_ARM64, FALSE,
                              native_runtime);
#endif
}
