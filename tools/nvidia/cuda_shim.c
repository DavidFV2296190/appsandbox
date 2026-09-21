#define COBJMACROS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <dxgi.h>
#include <winternl.h>
#include <d3dkmthk.h>
#pragma warning(pop)

#define CUDA_ERROR_NOT_INITIALIZED 3
#define CUDA_ERROR_NOT_SUPPORTED 801

typedef int (WINAPI *DeviceLuidFn)(char *, unsigned *, int);
typedef int (WINAPI *DeviceCountFn)(int *);
typedef int (WINAPI *DeviceGetFn)(int *, int);
typedef int (WINAPI *DevicePciFn)(char *, int, int);
typedef int (WINAPI *GetProcFn)(const char *, void **, int, unsigned __int64);
typedef int (WINAPI *GetProcV2Fn)(const char *, void **, int, unsigned __int64, int *);

static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static DeviceLuidFn g_get_luid;
static DeviceCountFn g_get_count;
static DeviceGetFn g_get_device;
static DevicePciFn g_get_pci;
static GetProcFn g_get_proc;
static GetProcV2Fn g_get_proc_v2;
static PFND3DKMT_OPENADAPTERFROMLUID g_open_adapter;
static PFND3DKMT_QUERYADAPTERINFO g_query_adapter;
static PFND3DKMT_CLOSEADAPTER g_close_adapter;

int WINAPI cuDeviceGetLuid(char *luid, unsigned *node_mask, int device);
int WINAPI cuGetProcAddress(const char *symbol, void **function, int version,
                           unsigned __int64 flags);
int WINAPI cuGetProcAddress_v2(const char *symbol, void **function, int version,
                              unsigned __int64 flags, int *status);

static BOOL CALLBACK load_cuda(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    HMODULE cuda, gdi32;
    (void)once;
    (void)parameter;
    (void)context;

    cuda = LoadLibraryExW(L"appsandbox-nvcuda.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!cuda) return TRUE;
    if (GetProcAddress(cuda, "appsandbox_cuda")) {
        FreeLibrary(cuda);
        return TRUE;
    }
    g_get_luid = (DeviceLuidFn)GetProcAddress(cuda, "cuDeviceGetLuid");
    g_get_count = (DeviceCountFn)GetProcAddress(cuda, "cuDeviceGetCount");
    g_get_device = (DeviceGetFn)GetProcAddress(cuda, "cuDeviceGet");
    g_get_pci = (DevicePciFn)GetProcAddress(cuda, "cuDeviceGetPCIBusId");
    g_get_proc = (GetProcFn)GetProcAddress(cuda, "cuGetProcAddress");
    g_get_proc_v2 = (GetProcV2Fn)GetProcAddress(cuda, "cuGetProcAddress_v2");
    gdi32 = LoadLibraryExW(L"gdi32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (gdi32) {
        g_open_adapter = (PFND3DKMT_OPENADAPTERFROMLUID)GetProcAddress(gdi32, "D3DKMTOpenAdapterFromLuid");
        g_query_adapter = (PFND3DKMT_QUERYADAPTERINFO)GetProcAddress(gdi32, "D3DKMTQueryAdapterInfo");
        g_close_adapter = (PFND3DKMT_CLOSEADAPTER)GetProcAddress(gdi32, "D3DKMTCloseAdapter");
    }
    return TRUE;
}

static BOOL device_address(int device, D3DKMT_ADAPTERADDRESS *address)
{
    char pci[64] = {0}, trailing;
    unsigned domain;

    if (g_get_pci(pci, sizeof(pci), device) != 0) return FALSE;
    pci[sizeof(pci) - 1] = '\0';
    return sscanf_s(pci, "%x:%x:%x.%x%c", &domain, &address->BusNumber,
                    &address->DeviceNumber, &address->FunctionNumber, &trailing, 1u) == 4;
}

static BOOL query_adapter(D3DKMT_HANDLE adapter, KMTQUERYADAPTERINFOTYPE type,
                          void *data, UINT size)
{
    D3DKMT_QUERYADAPTERINFO query = {0};
    query.hAdapter = adapter;
    query.Type = type;
    query.pPrivateDriverData = data;
    query.PrivateDriverDataSize = size;
    return g_query_adapter(&query) >= 0;
}

static BOOL guest_device_luid(int device, LUID *luid)
{
    D3DKMT_ADAPTERADDRESS wanted;
    IDXGIFactory1 *factory = NULL;
    int count, cuda_matches = 0;
    unsigned guest_matches = 0;
    LUID selected = {0};
    D3DKMT_QUERY_DEVICE_IDS selected_ids = {0};
    BOOL complete = FALSE, ambiguous = FALSE;

    if (!g_get_count || !g_get_device || !g_get_pci || !g_open_adapter ||
        !g_query_adapter || !g_close_adapter || !device_address(device, &wanted) ||
        g_get_count(&count) != 0)
        return FALSE;
    /* KMT omits the PCI domain, so a BDF shared by multiple devices is ambiguous. */
    for (int i = 0; i < count; ++i) {
        int candidate;
        D3DKMT_ADAPTERADDRESS address;
        if (g_get_device(&candidate, i) != 0 || !device_address(candidate, &address))
            return FALSE;
        if (memcmp(&address, &wanted, sizeof(address)) == 0) ++cuda_matches;
    }
    if (cuda_matches != 1 || FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void **)&factory)))
        return FALSE;
    for (UINT i = 0; ; ++i) {
        IDXGIAdapter1 *adapter = NULL;
        DXGI_ADAPTER_DESC1 desc;
        D3DKMT_OPENADAPTERFROMLUID open = {0};
        D3DKMT_CLOSEADAPTER close = {0};
        D3DKMT_ADAPTERTYPE type = {0};
        D3DKMT_QUERY_DEVICE_IDS ids = {0};
        D3DKMT_ADAPTERADDRESS address;
        HRESULT result = IDXGIFactory1_EnumAdapters1(factory, i, &adapter);

        if (result == DXGI_ERROR_NOT_FOUND) {
            complete = TRUE;
            break;
        }
        if (result != S_OK) break;
        result = IDXGIAdapter1_GetDesc1(adapter, &desc);
        IDXGIAdapter1_Release(adapter);
        if (FAILED(result) || desc.VendorId != 0x10de ||
            (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) continue;
        open.AdapterLuid = desc.AdapterLuid;
        if (g_open_adapter(&open) < 0) continue;
        if (query_adapter(open.hAdapter, KMTQAITYPE_ADAPTERTYPE_RENDER, &type, sizeof(type)) &&
            type.Paravirtualized &&
            query_adapter(open.hAdapter, KMTQAITYPE_PHYSICALADAPTERDEVICEIDS, &ids, sizeof(ids)) &&
            ids.DeviceIds.VendorID == 0x10de && ids.DeviceIds.DeviceID == desc.DeviceId &&
            query_adapter(open.hAdapter, KMTQAITYPE_ADAPTERADDRESS_RENDER, &address, sizeof(address)) &&
            memcmp(&address, &wanted, sizeof(address)) == 0) {
            if (!guest_matches) {
                selected = desc.AdapterLuid;
                selected_ids = ids;
            } else if (memcmp(&selected_ids.DeviceIds, &ids.DeviceIds, sizeof(ids.DeviceIds)) != 0) {
                ambiguous = TRUE;
            }
            ++guest_matches;
        }
        close.hAdapter = open.hAdapter;
        g_close_adapter(&close);
    }
    IDXGIFactory1_Release(factory);
    if (!complete || !guest_matches || ambiguous || (!selected.LowPart && !selected.HighPart))
        return FALSE;
    *luid = selected;
    return TRUE;
}

int WINAPI cuDeviceGetLuid(char *luid, unsigned *node_mask, int device)
{
    LUID guest;
    int result;
    InitOnceExecuteOnce(&g_once, load_cuda, NULL, NULL);
    if (!g_get_luid) return CUDA_ERROR_NOT_INITIALIZED;
    result = g_get_luid(luid, node_mask, device);
    if (result == 0 && luid && node_mask && *node_mask == 1 && guest_device_luid(device, &guest))
        memcpy(luid, &guest, sizeof(guest));
    return result;
}

static void wrap_function(const char *symbol, void **function, int version)
{
    if (!symbol || !function || !*function) return;
    if (strcmp(symbol, "cuDeviceGetLuid") == 0)
        *function = (void *)cuDeviceGetLuid;
    else if (strcmp(symbol, "cuGetProcAddress") == 0)
        *function = version >= 12000 ? (void *)cuGetProcAddress_v2 : (void *)cuGetProcAddress;
    else if (strcmp(symbol, "cuGetProcAddress_v2") == 0)
        *function = (void *)cuGetProcAddress_v2;
}

int WINAPI cuGetProcAddress(const char *symbol, void **function, int version,
                           unsigned __int64 flags)
{
    int result;
    InitOnceExecuteOnce(&g_once, load_cuda, NULL, NULL);
    if (!g_get_proc) return CUDA_ERROR_NOT_SUPPORTED;
    result = g_get_proc(symbol, function, version, flags);
    if (result == 0) wrap_function(symbol, function, version);
    return result;
}

int WINAPI cuGetProcAddress_v2(const char *symbol, void **function, int version,
                              unsigned __int64 flags, int *status)
{
    int result;
    InitOnceExecuteOnce(&g_once, load_cuda, NULL, NULL);
    if (!g_get_proc_v2) return CUDA_ERROR_NOT_SUPPORTED;
    result = g_get_proc_v2(symbol, function, version, flags, status);
    if (result == 0) wrap_function(symbol, function, version);
    return result;
}

DWORD __cdecl appsandbox_cuda(void)
{
    return 0x41534201;
}
