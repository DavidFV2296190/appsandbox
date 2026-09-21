#define COBJMACROS
#include <windows.h>
#include "cuda_opencl_adapter_hooks.h"

#if defined(_M_X64)
#include <intrin.h>
#include <stdio.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <dxgi.h>
#include <winternl.h>
#include <d3dkmthk.h>
#pragma warning(pop)

typedef HRESULT (STDMETHODCALLTYPE *AdapterGetDescFn)(IDXGIAdapter *, DXGI_ADAPTER_DESC *);
typedef int (WINAPI *CudaDeviceCountFn)(int *);
typedef int (WINAPI *CudaDeviceGetFn)(int *, int);
typedef int (WINAPI *CudaDevicePciFn)(char *, int, int);
typedef int (WINAPI *CudaDeviceLuidFn)(char *, unsigned *, int);

typedef struct ComputeAdapter {
    struct ComputeAdapter *next;
    IDXGIAdapter1 *adapter;
    LUID guest_luid;
    D3DKMT_ADAPTERADDRESS address;
    LUID cuda_luid;
    BOOL have_cuda_luid;
    HMODULE opencl;
    LUID opencl_luid;
} ComputeAdapter;

static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static SRWLOCK g_luid_lock = SRWLOCK_INIT;
static ComputeAdapter *g_adapters;
static AdapterGetDescFn g_adapter_get_desc;
static PFND3DKMT_OPENADAPTERFROMLUID g_open_luid;
static PFND3DKMT_QUERYADAPTERINFO g_query_adapter;
static PFND3DKMT_CLOSEADAPTER g_close_adapter;
static __declspec(thread) BOOL g_resolving;

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

static BOOL guest_adapter_address(const DXGI_ADAPTER_DESC *desc,
                                  D3DKMT_ADAPTERADDRESS *address)
{
    D3DKMT_OPENADAPTERFROMLUID open = {0};
    D3DKMT_CLOSEADAPTER close = {0};
    D3DKMT_ADAPTERTYPE type = {0};
    D3DKMT_QUERY_DEVICE_IDS ids = {0};
    BOOL found;

    open.AdapterLuid = desc->AdapterLuid;
    if (g_open_luid(&open) < 0) return FALSE;
    found = query_adapter(open.hAdapter, KMTQAITYPE_ADAPTERTYPE_RENDER, &type, sizeof(type)) &&
        type.Paravirtualized &&
        query_adapter(open.hAdapter, KMTQAITYPE_PHYSICALADAPTERDEVICEIDS, &ids, sizeof(ids)) &&
        ids.DeviceIds.VendorID == 0x10de && ids.DeviceIds.DeviceID == desc->DeviceId &&
        query_adapter(open.hAdapter, KMTQAITYPE_ADAPTERADDRESS_RENDER, address, sizeof(*address));
    close.hAdapter = open.hAdapter;
    g_close_adapter(&close);
    return found;
}

static BOOL cuda_adapter_luid(HMODULE cuda, const D3DKMT_ADAPTERADDRESS *address, LUID *luid)
{
    if (GetProcAddress(cuda, "appsandbox_cuda")) {
        cuda = GetModuleHandleW(L"appsandbox-nvcuda.dll");
        if (!cuda) return FALSE;
    }
    CudaDeviceCountFn get_count = (CudaDeviceCountFn)GetProcAddress(cuda, "cuDeviceGetCount");
    CudaDeviceGetFn get_device = (CudaDeviceGetFn)GetProcAddress(cuda, "cuDeviceGet");
    CudaDevicePciFn get_pci = (CudaDevicePciFn)GetProcAddress(cuda, "cuDeviceGetPCIBusId");
    CudaDeviceLuidFn get_luid = (CudaDeviceLuidFn)GetProcAddress(cuda, "cuDeviceGetLuid");
    LUID selected = {0};
    int count = 0, matches = 0;

    /* CUDA is already calling GetDesc. Reentering cuInit here can deadlock. */
    if (!get_count || !get_device || !get_pci || !get_luid ||
        get_count(&count) != 0 || count <= 0)
        return FALSE;
    for (int i = 0; i < count; ++i) {
        char pci[64] = {0}, trailing;
        unsigned domain, bus, device, function, node_mask = 0;
        int cuda_device;

        if (get_device(&cuda_device, i) != 0 ||
            get_pci(pci, (int)sizeof(pci), cuda_device) != 0)
            return FALSE;
        pci[sizeof(pci) - 1] = '\0';
        if (sscanf_s(pci, "%x:%x:%x.%x%c", &domain, &bus, &device, &function,
                     &trailing, 1u) != 4)
            return FALSE;
        /* KMT has no PCI domain field, so require an unambiguous BDF match. */
        if (bus != address->BusNumber || device != address->DeviceNumber ||
            function != address->FunctionNumber)
            continue;
        if (++matches != 1 || get_luid((char *)&selected, &node_mask, cuda_device) != 0 ||
            node_mask != 1 || (!selected.LowPart && !selected.HighPart))
            return FALSE;
    }
    if (matches != 1) return FALSE;
    *luid = selected;
    return TRUE;
}

static BOOL cached_cuda_luid(HMODULE cuda, ComputeAdapter *adapter, LUID *luid)
{
    BOOL found;
    LUID resolved;

    AcquireSRWLockShared(&g_luid_lock);
    found = adapter->have_cuda_luid;
    if (found) *luid = adapter->cuda_luid;
    ReleaseSRWLockShared(&g_luid_lock);
    if (found) return TRUE;
    if (!cuda_adapter_luid(cuda, &adapter->address, &resolved)) return FALSE;
    AcquireSRWLockExclusive(&g_luid_lock);
    if (!adapter->have_cuda_luid) {
        adapter->cuda_luid = resolved;
        adapter->have_cuda_luid = TRUE;
    }
    *luid = adapter->cuda_luid;
    ReleaseSRWLockExclusive(&g_luid_lock);
    return TRUE;
}

static HRESULT STDMETHODCALLTYPE compute_adapter_get_desc(IDXGIAdapter *adapter, DXGI_ADAPTER_DESC *desc)
{
    HRESULT result = g_adapter_get_desc(adapter, desc);
    MEMORY_BASIC_INFORMATION caller;
    HMODULE cuda, implementation, loader;
    ComputeAdapter *entry;
    LUID luid;

    if (FAILED(result) || !desc || desc->VendorId != 0x10de || g_resolving)
        return result;
    cuda = GetModuleHandleW(L"nvcuda.dll");
    implementation = GetModuleHandleW(L"nvcuda64.dll");
    loader = GetModuleHandleW(L"appsandbox-nvcuda.dll");
    if (!VirtualQuery(_ReturnAddress(), &caller, sizeof(caller))) return result;

    /* Only CUDA/OpenCL driver callers need host LUIDs; applications need guest LUIDs. */
    for (entry = g_adapters; entry; entry = entry->next) {
        if (entry->guest_luid.LowPart == desc->AdapterLuid.LowPart &&
            entry->guest_luid.HighPart == desc->AdapterLuid.HighPart)
            break;
    }
    if (!entry) return result;
    AcquireSRWLockShared(&g_luid_lock);
    if (entry->opencl && caller.AllocationBase == entry->opencl) {
        desc->AdapterLuid = entry->opencl_luid;
        ReleaseSRWLockShared(&g_luid_lock);
        return result;
    }
    ReleaseSRWLockShared(&g_luid_lock);
    if (caller.AllocationBase != cuda && caller.AllocationBase != implementation &&
        caller.AllocationBase != loader) return result;
    g_resolving = TRUE;
    if (cached_cuda_luid(loader ? loader : cuda ? cuda : implementation, entry, &luid))
        desc->AdapterLuid = luid;
    g_resolving = FALSE;
    return result;
}

static void free_adapters(ComputeAdapter *adapters)
{
    while (adapters) {
        ComputeAdapter *next = adapters->next;
        if (adapters->adapter) IDXGIAdapter1_Release(adapters->adapter);
        HeapFree(GetProcessHeap(), 0, adapters);
        adapters = next;
    }
}

static BOOL CALLBACK install_compute_hook(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    HMODULE gdi32, pinned;
    IDXGIFactory1 *factory = NULL;
    ComputeAdapter *adapters = NULL, **tail = &adapters, *entry;
    BOOL installed = FALSE;
    UINT i;
    (void)once;
    (void)parameter;
    (void)context;

    gdi32 = LoadLibraryExW(L"gdi32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!gdi32) return FALSE;
    g_open_luid = (PFND3DKMT_OPENADAPTERFROMLUID)GetProcAddress(gdi32, "D3DKMTOpenAdapterFromLuid");
    g_query_adapter = (PFND3DKMT_QUERYADAPTERINFO)GetProcAddress(gdi32, "D3DKMTQueryAdapterInfo");
    g_close_adapter = (PFND3DKMT_CLOSEADAPTER)GetProcAddress(gdi32, "D3DKMTCloseAdapter");
    if (!g_open_luid || !g_query_adapter || !g_close_adapter ||
        FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void **)&factory))) goto failed;
    for (i = 0; ; ++i) {
        IDXGIAdapter1 *adapter = NULL;
        DXGI_ADAPTER_DESC desc;
        D3DKMT_ADAPTERADDRESS address = {0};
        HRESULT result = IDXGIFactory1_EnumAdapters1(factory, i, &adapter);

        if (result == DXGI_ERROR_NOT_FOUND) break;
        if (result != S_OK) goto failed;
        if (FAILED(IDXGIAdapter1_GetDesc(adapter, &desc)) || desc.VendorId != 0x10de ||
            !guest_adapter_address(&desc, &address)) {
            IDXGIAdapter1_Release(adapter);
            continue;
        }
        entry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*entry));
        if (!entry) {
            IDXGIAdapter1_Release(adapter);
            goto failed;
        }
        entry->adapter = adapter;
        entry->guest_luid = desc.AdapterLuid;
        entry->address = address;
        *tail = entry;
        tail = &entry->next;
    }
    IDXGIFactory1_Release(factory);
    factory = NULL;
    if (!adapters) {
        FreeLibrary(gdi32);
        return TRUE;
    }

    g_adapters = adapters;
    for (entry = adapters; entry; entry = entry->next) {
        void *volatile *slot;
        void *original;
        DWORD protection, unused;

        slot = (void *volatile *)&entry->adapter->lpVtbl->GetDesc;
        original = *slot;
        if (original && original != (void *)compute_adapter_get_desc &&
            (!g_adapter_get_desc || original == (void *)g_adapter_get_desc) &&
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                              (LPCWSTR)compute_adapter_get_desc, &pinned) &&
            VirtualProtect((void *)slot, sizeof(*slot), PAGE_READWRITE, &protection)) {
            g_adapter_get_desc = (AdapterGetDescFn)original;
            if (InterlockedCompareExchangePointer(slot, (void *)compute_adapter_get_desc, original) == original)
                installed = TRUE;
            else if (!installed)
                g_adapter_get_desc = NULL;
            VirtualProtect((void *)slot, sizeof(*slot), protection, &unused);
        }
        IDXGIAdapter1_Release(entry->adapter);
        entry->adapter = NULL;
    }
    if (installed) return TRUE;
    g_adapters = NULL;
    g_adapter_get_desc = NULL;
failed:
    if (factory) IDXGIFactory1_Release(factory);
    free_adapters(adapters);
    FreeLibrary(gdi32);
    return FALSE;
}

void nvidia_install_cuda_adapter_hook(void)
{
    if (GetModuleHandleW(L"nvcuda.dll") || GetModuleHandleW(L"nvcuda64.dll") ||
        GetModuleHandleW(L"appsandbox-nvcuda.dll"))
        InitOnceExecuteOnce(&g_once, install_compute_hook, NULL, NULL);
}

BOOL WINAPI appsandbox_nvidia_register_opencl_adapter(HMODULE module, const LUID *guest, const LUID *host)
{
    ComputeAdapter *entry;
    HMODULE pinned;
    BOOL result = FALSE;

    if (!module || !guest || !host || (!host->LowPart && !host->HighPart) ||
        !InitOnceExecuteOnce(&g_once, install_compute_hook, NULL, NULL)) return FALSE;
    for (entry = g_adapters; entry; entry = entry->next) {
        if (entry->guest_luid.LowPart != guest->LowPart ||
            entry->guest_luid.HighPart != guest->HighPart) continue;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                              (LPCWSTR)module, &pinned)) return FALSE;
        AcquireSRWLockExclusive(&g_luid_lock);
        if (!entry->opencl || (entry->opencl == module &&
            entry->opencl_luid.LowPart == host->LowPart && entry->opencl_luid.HighPart == host->HighPart)) {
            entry->opencl = module;
            entry->opencl_luid = *host;
            result = TRUE;
        }
        ReleaseSRWLockExclusive(&g_luid_lock);
        break;
    }
    return result;
}

#else

void nvidia_install_cuda_adapter_hook(void)
{
}

BOOL WINAPI appsandbox_nvidia_register_opencl_adapter(HMODULE module, const LUID *guest, const LUID *host)
{
    (void)module;
    (void)guest;
    (void)host;
    return FALSE;
}

#endif
