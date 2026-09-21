#define COBJMACROS
#include <windows.h>
#include <stddef.h>
#include <string.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <dxgi.h>
#include <winternl.h>
#include <d3dkmthk.h>
#pragma warning(pop)

#define CL_SUCCESS 0
#define CL_INVALID_VALUE (-30)
#define CL_INVALID_DEVICE (-33)
#define CL_PLATFORM_NOT_FOUND_KHR (-1001)
#define CL_DEVICE_TYPE_GPU 4
#define CL_DEVICE_VENDOR_ID 0x1001
#define CL_DEVICE_LUID_VALID_KHR 0x106c
#define CL_DEVICE_LUID_KHR 0x106d
#define CL_DEVICE_NODE_MASK_KHR 0x106e
#define CL_DEVICE_PCI_BUS_INFO_KHR 0x410f

typedef void *ClPlatform;
typedef void *ClDevice;
typedef int (WINAPI *PlatformsFn)(UINT, ClPlatform *, UINT *);
typedef int (WINAPI *PlatformInfoFn)(ClPlatform, UINT, size_t, void *, size_t *);
typedef int (WINAPI *DevicesFn)(ClPlatform, ULONGLONG, UINT, ClDevice *, UINT *);
typedef int (WINAPI *DeviceInfoFn)(ClDevice, UINT, size_t, void *, size_t *);
typedef void *(WINAPI *ExtensionFn)(const char *);
typedef void *(WINAPI *PlatformFunctionFn)(ClPlatform, const char *);
typedef int (WINAPI *PlatformDispatchFn)(ClPlatform, void *);
typedef BOOL (WINAPI *RegisterAdapterFn)(HMODULE, const LUID *, const LUID *);

/* The ICD ABI appends entries; the OpenCL 1.0 dispatch prefix is fixed. */
typedef struct {
    PlatformsFn get_platforms;
    PlatformInfoFn get_platform_info;
    DevicesFn get_devices;
    DeviceInfoFn get_device_info;
} ClDispatch;
C_ASSERT(offsetof(ClDispatch, get_device_info) == 3 * sizeof(void *));

typedef struct {
    UINT domain, bus, device, function;
} ClPciInfo;

typedef struct ClAdapter {
    struct ClAdapter *next;
    ClDevice device;
    ClDispatch *dispatch;
    DeviceInfoFn get_device_info;
    ClPciInfo pci;
    LUID host_luid;
    LUID guest_luid;
    BOOL mapped;
} ClAdapter;

static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
static HMODULE g_driver;
static PlatformsFn g_platforms;
static PlatformInfoFn g_platform_info;
static ExtensionFn g_extension;
static PlatformFunctionFn g_platform_function;
static PlatformDispatchFn g_platform_dispatch;
static ClAdapter *g_adapters;
static PFND3DKMT_OPENADAPTERFROMLUID g_open_luid;
static PFND3DKMT_QUERYADAPTERINFO g_query_adapter;
static PFND3DKMT_CLOSEADAPTER g_close_adapter;

int WINAPI clIcdGetPlatformIDsKHR(UINT count, ClPlatform *platforms, UINT *total);
void *WINAPI clGetExtensionFunctionAddress(const char *name);
void *WINAPI clIcdGetFunctionAddressForPlatformKHR(ClPlatform platform, const char *name);

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

static BOOL adapter_address(const DXGI_ADAPTER_DESC1 *desc, D3DKMT_ADAPTERADDRESS *address)
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

static int WINAPI device_info_hook(ClDevice device, UINT name, size_t capacity,
                                   void *value, size_t *size)
{
    ClDispatch *dispatch;
    ClAdapter *entry;
    DeviceInfoFn function = NULL;
    int result;

    if (!device) return CL_INVALID_DEVICE;
    dispatch = *(ClDispatch **)device;
    for (entry = g_adapters; entry; entry = entry->next) {
        if (entry->device == device) {
            function = entry->get_device_info;
            break;
        }
        if (entry->dispatch == dispatch) function = entry->get_device_info;
    }
    if (!function) return CL_INVALID_VALUE;
    result = function(device, name, capacity, value, size);
    if (result == CL_SUCCESS && entry && entry->mapped && value &&
        name == CL_DEVICE_LUID_KHR && capacity >= sizeof(LUID))
        memcpy(value, &entry->guest_luid, sizeof(LUID));
    return result;
}

static BOOL enumerate_devices(void)
{
    ClPlatform *platforms = NULL;
    UINT count = 0, i;
    BOOL result = FALSE;

    if (g_platforms(0, NULL, &count) != CL_SUCCESS || !count) return FALSE;
    platforms = HeapAlloc(GetProcessHeap(), 0, count * sizeof(*platforms));
    if (!platforms || g_platforms(count, platforms, NULL) != CL_SUCCESS) goto done;
    for (i = 0; i < count; ++i) {
        ClDispatch *dispatch = *(ClDispatch **)platforms[i];
        ClDevice *devices;
        DevicesFn get_devices = dispatch->get_devices;
        DeviceInfoFn get_info = dispatch->get_device_info;
        UINT device_count = 0, j;

        if (g_platform_function) {
            get_devices = (DevicesFn)g_platform_function(platforms[i], "clGetDeviceIDs");
            get_info = (DeviceInfoFn)g_platform_function(platforms[i], "clGetDeviceInfo");
        }
        if (!get_devices || !get_info ||
            get_devices(platforms[i], CL_DEVICE_TYPE_GPU, 0, NULL, &device_count) != CL_SUCCESS ||
            !device_count) continue;
        devices = HeapAlloc(GetProcessHeap(), 0, device_count * sizeof(*devices));
        if (!devices) goto done;
        if (get_devices(platforms[i], CL_DEVICE_TYPE_GPU, device_count, devices, NULL) != CL_SUCCESS) {
            HeapFree(GetProcessHeap(), 0, devices);
            goto done;
        }
        for (j = 0; j < device_count; ++j) {
            UINT vendor = 0, valid = 0, node_mask = 0;
            ClPciInfo pci;
            LUID luid;
            ClAdapter *entry;

            if (get_info(devices[j], CL_DEVICE_VENDOR_ID, sizeof(vendor), &vendor, NULL) || vendor != 0x10de ||
                get_info(devices[j], CL_DEVICE_LUID_VALID_KHR, sizeof(valid), &valid, NULL) || !valid ||
                get_info(devices[j], CL_DEVICE_NODE_MASK_KHR, sizeof(node_mask), &node_mask, NULL) || node_mask != 1 ||
                get_info(devices[j], CL_DEVICE_PCI_BUS_INFO_KHR, sizeof(pci), &pci, NULL) ||
                get_info(devices[j], CL_DEVICE_LUID_KHR, sizeof(luid), &luid, NULL) ||
                (!luid.LowPart && !luid.HighPart)) continue;
            entry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*entry));
            if (!entry) {
                HeapFree(GetProcessHeap(), 0, devices);
                goto done;
            }
            entry->device = devices[j];
            entry->dispatch = *(ClDispatch **)devices[j];
            entry->get_device_info = get_info;
            entry->pci = pci;
            entry->host_luid = luid;
            entry->next = g_adapters;
            g_adapters = entry;
        }
        HeapFree(GetProcessHeap(), 0, devices);
    }
    result = TRUE;
done:
    if (platforms) HeapFree(GetProcessHeap(), 0, platforms);
    return result;
}

static void map_adapters(void)
{
    HMODULE gdi = LoadLibraryExW(L"gdi32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    HMODULE nvapi = LoadLibraryExW(L"nvapi64.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    IDXGIFactory1 *factory = NULL;
    RegisterAdapterFn register_adapter = nvapi ?
        (RegisterAdapterFn)GetProcAddress(nvapi, "appsandbox_nvidia_register_opencl_adapter") : NULL;
    ClAdapter *entry;
    UINT i;

    if (!gdi) goto done;
    g_open_luid = (PFND3DKMT_OPENADAPTERFROMLUID)GetProcAddress(gdi, "D3DKMTOpenAdapterFromLuid");
    g_query_adapter = (PFND3DKMT_QUERYADAPTERINFO)GetProcAddress(gdi, "D3DKMTQueryAdapterInfo");
    g_close_adapter = (PFND3DKMT_CLOSEADAPTER)GetProcAddress(gdi, "D3DKMTCloseAdapter");
    if (!g_open_luid || !g_query_adapter || !g_close_adapter ||
        FAILED(CreateDXGIFactory1(&IID_IDXGIFactory1, (void **)&factory))) goto done;
    for (i = 0; ; ++i) {
        IDXGIAdapter1 *adapter = NULL;
        DXGI_ADAPTER_DESC1 desc;
        D3DKMT_ADAPTERADDRESS address;
        ClAdapter *match = NULL;
        UINT matches = 0;

        if (IDXGIFactory1_EnumAdapters1(factory, i, &adapter) != S_OK) break;
        if (FAILED(IDXGIAdapter1_GetDesc1(adapter, &desc)) || desc.VendorId != 0x10de ||
            !adapter_address(&desc, &address)) {
            IDXGIAdapter1_Release(adapter);
            continue;
        }
        IDXGIAdapter1_Release(adapter);
        for (entry = g_adapters; entry; entry = entry->next) {
            if (entry->pci.bus == address.BusNumber && entry->pci.device == address.DeviceNumber &&
                entry->pci.function == address.FunctionNumber) {
                match = entry;
                ++matches;
            }
        }
        if (matches != 1) continue;
        if (!match->mapped) {
            match->guest_luid = desc.AdapterLuid;
            match->mapped = TRUE;
        }
        if (register_adapter) register_adapter(g_driver, &desc.AdapterLuid, &match->host_luid);
    }
done:
    if (factory) IDXGIFactory1_Release(factory);
    if (gdi) FreeLibrary(gdi);
    if (nvapi) FreeLibrary(nvapi);
}

static void install_device_info_hooks(void)
{
    ClAdapter *entry;
    HMODULE pinned;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                           (LPCWSTR)device_info_hook, &pinned)) return;
    for (entry = g_adapters; entry; entry = entry->next) {
        void *volatile *slot = (void *volatile *)&entry->dispatch->get_device_info;
        DWORD protection, unused;
        if (!entry->mapped || *slot == (void *)device_info_hook) continue;
        if (VirtualProtect((void *)slot, sizeof(*slot), PAGE_READWRITE, &protection)) {
            InterlockedCompareExchangePointer(slot, (void *)device_info_hook, (void *)entry->get_device_info);
            VirtualProtect((void *)slot, sizeof(*slot), protection, &unused);
        }
    }
}

static BOOL CALLBACK load_opencl(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    HMODULE self;
    wchar_t path[MAX_PATH], *name;
    DWORD length;
    (void)once;
    (void)parameter;
    (void)context;

    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)load_opencl, &self)) return TRUE;
    length = GetModuleFileNameW(self, path, ARRAYSIZE(path));
    if (!length || length >= ARRAYSIZE(path)) return TRUE;
    name = wcsrchr(path, L'\\');
    if (!name) return TRUE;
    wcscpy_s(name + 1, ARRAYSIZE(path) - (size_t)(name + 1 - path), L"appsandbox-nvopencl64.dll");
    g_driver = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!g_driver || g_driver == self) return TRUE;
    g_extension = (ExtensionFn)GetProcAddress(g_driver, "clGetExtensionFunctionAddress");
    g_platform_info = (PlatformInfoFn)GetProcAddress(g_driver, "clGetPlatformInfo");
    if (!g_extension || !g_platform_info) return TRUE;
    g_platforms = (PlatformsFn)g_extension("clIcdGetPlatformIDsKHR");
    g_platform_function = (PlatformFunctionFn)g_extension("clIcdGetFunctionAddressForPlatformKHR");
    g_platform_dispatch = (PlatformDispatchFn)g_extension("clIcdSetPlatformDispatchDataKHR");
    if (g_platforms && enumerate_devices()) {
        map_adapters();
        install_device_info_hooks();
    }
    return TRUE;
}

int WINAPI clIcdGetPlatformIDsKHR(UINT count, ClPlatform *platforms, UINT *total)
{
    InitOnceExecuteOnce(&g_once, load_opencl, NULL, NULL);
    return g_platforms ? g_platforms(count, platforms, total) : CL_PLATFORM_NOT_FOUND_KHR;
}

int WINAPI clGetPlatformInfo(ClPlatform platform, UINT name, size_t capacity, void *value, size_t *size)
{
    InitOnceExecuteOnce(&g_once, load_opencl, NULL, NULL);
    return g_platform_info ? g_platform_info(platform, name, capacity, value, size) : CL_INVALID_VALUE;
}

void *WINAPI clIcdGetFunctionAddressForPlatformKHR(ClPlatform platform, const char *name)
{
    void *function;
    InitOnceExecuteOnce(&g_once, load_opencl, NULL, NULL);
    if (!name || !g_platform_function) return NULL;
    function = g_platform_function(platform, name);
    if (function && strcmp(name, "clGetDeviceInfo") == 0 && g_adapters)
        return (void *)device_info_hook;
    return function;
}

int WINAPI clIcdSetPlatformDispatchDataKHR(ClPlatform platform, void *data)
{
    InitOnceExecuteOnce(&g_once, load_opencl, NULL, NULL);
    return g_platform_dispatch ? g_platform_dispatch(platform, data) : CL_INVALID_VALUE;
}

void *WINAPI clGetExtensionFunctionAddress(const char *name)
{
    InitOnceExecuteOnce(&g_once, load_opencl, NULL, NULL);
    if (!name || !g_extension) return NULL;
    if (strcmp(name, "clIcdGetPlatformIDsKHR") == 0 && g_platforms)
        return (void *)clIcdGetPlatformIDsKHR;
    if (strcmp(name, "clIcdGetFunctionAddressForPlatformKHR") == 0 && g_platform_function)
        return (void *)clIcdGetFunctionAddressForPlatformKHR;
    if (strcmp(name, "clIcdSetPlatformDispatchDataKHR") == 0 && g_platform_dispatch)
        return (void *)clIcdSetPlatformDispatchDataKHR;
    return g_extension(name);
}

BOOL WINAPI appsandbox_opencl(void)
{
    return TRUE;
}
