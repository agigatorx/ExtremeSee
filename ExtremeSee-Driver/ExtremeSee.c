/*++
 *
 *  ExtremeSee - DriverEntry / DriverUnload
 *
--*/

#include "ExtremeSee.h"

DRIVER_INITIALIZE DriverEntry;

static VOID ExtremeSeeUnload(_In_ PDRIVER_OBJECT DriverObject);

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    WCHAR    text[160];

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Make sure unload is possible before anything is registered. */
    DriverObject->DriverUnload = ExtremeSeeUnload;

    status = EsLogInit();
    if (!NT_SUCCESS(status)) {
        DbgPrint("ExtremeSee: log engine init failed (0x%08x)\n", status);
        return status;
    }

    EsLogEvent("Info", L"ExtremeSee driver loaded");

    /* Process creation / termination callbacks. */
    /*
     * Process monitoring is the core feature, but if registration fails
     * (e.g. the image lacks IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY /
     * /INTEGRITYCHECK) we still start so the log file can tell what is
     * wrong instead of SCM showing a generic "Access denied".
     */
    status = EsProcessInit();
    if (NT_SUCCESS(status)) {
        EsLogEvent("Info", L"Process monitoring active");
    } else {
        WCHAR hex[9];
        EsStatusHex(status, hex);
        RtlStringCchCopyW(text, RTL_NUMBER_OF(text), L"process monitoring unavailable ");
        RtlStringCchCatW(text, RTL_NUMBER_OF(text), hex);
        EsLogEvent("Warning", text);
        DbgPrint("ExtremeSee: process notify registration failed (0x%08x)\n", status);
    }

    /*
     * File monitoring (minifilter). Failure is not fatal: it happens e.g.
     * when the altitude registry keys are missing (sc create without the
     * install script). Process logging keeps working in that case.
     */
    status = EsFileInit(DriverObject);
    if (NT_SUCCESS(status)) {
        EsLogEvent("Info", L"File monitoring active");
    } else {
        WCHAR hex[9];
        EsStatusHex(status, hex);
        RtlStringCchCopyW(text, RTL_NUMBER_OF(text), L"file monitoring unavailable ");
        RtlStringCchCatW(text, RTL_NUMBER_OF(text), hex);
        EsLogEvent("Warning", text);
        DbgPrint("ExtremeSee: file monitoring init failed (0x%08x)\n", status);
    }

    DbgPrint("ExtremeSee: loaded\n");
    return STATUS_SUCCESS;
}

static VOID ExtremeSeeUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    EsLogEvent("Info", L"ExtremeSee driver unloading");

    /*
     * 1) First unregister every producer of log events.
     *    Both calls block until in-flight callbacks have finished.
     * 2) Then stop the writer thread and drain what is left.
     */
    EsProcessShutdown();
    EsFileShutdown();
    EsLogShutdown();

    DbgPrint("ExtremeSee: unloaded\n");
}
