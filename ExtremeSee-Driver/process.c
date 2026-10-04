/*++
 *
 *  ExtremeSee - Process creation / termination logging
 *
 *  Uses PsSetCreateProcessNotifyRoutineEx. The callback runs at
 *  PASSIVE_LEVEL and gives us the full command line, so entries look
 *  like:
 *
 *    2026-10-04 12:33:01 [Process Created] powershell.exe -WindowStyle Hidden (PID: 4521)
 *    2026-10-04 12:33:05 [Process Ended] powershell.exe (PID: 4521)
 *
 *  To print a name for [Process Ended] we keep a small pid -> name table.
 *
--*/

#include "ExtremeSee.h"

typedef struct _ES_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE     ProcessId;
    WCHAR      Name[ES_NAME_CCH];
} ES_PROCESS_ENTRY, *PES_PROCESS_ENTRY;

static LIST_ENTRY    g_ProcessList;
static FAST_MUTEX    g_ProcessLock;
static volatile LONG g_ProcessCount;
static BOOLEAN       g_Registered = FALSE;

static VOID EsProcessNotify(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

/* ------------------------------------------------------------------ */
/* pid -> name table                                                   */
/* ------------------------------------------------------------------ */

static VOID EsRememberProcess(HANDLE ProcessId, PCWSTR Name)
{
    PES_PROCESS_ENTRY entry;

    if (InterlockedIncrement(&g_ProcessCount) > ES_MAX_TRACKED_PROCESSES) {
        InterlockedDecrement(&g_ProcessCount);
        return;                          /* table full: PID-only logs */
    }

    entry = (PES_PROCESS_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                               sizeof(ES_PROCESS_ENTRY),
                                               ES_POOL_TAG);
    if (entry == NULL) {
        InterlockedDecrement(&g_ProcessCount);
        return;
    }

    entry->ProcessId = ProcessId;
    RtlStringCchCopyW(entry->Name, ES_NAME_CCH, Name);

    ExAcquireFastMutex(&g_ProcessLock);
    InsertHeadList(&g_ProcessList, &entry->ListEntry);
    ExReleaseFastMutex(&g_ProcessLock);
}

static BOOLEAN EsForgetProcess(HANDLE ProcessId, PWCHAR Out, SIZE_T OutCch)
{
    PLIST_ENTRY link;
    BOOLEAN     found = FALSE;

    Out[0] = L'\0';

    ExAcquireFastMutex(&g_ProcessLock);
    for (link = g_ProcessList.Flink; link != &g_ProcessList; link = link->Flink) {
        PES_PROCESS_ENTRY entry = CONTAINING_RECORD(link, ES_PROCESS_ENTRY, ListEntry);

        if (entry->ProcessId == ProcessId) {
            RemoveEntryList(&entry->ListEntry);
            RtlStringCchCopyW(Out, OutCch, entry->Name);
            ExFreePoolWithTag(entry, ES_POOL_TAG);
            found = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_ProcessLock);

    if (found) {
        InterlockedDecrement(&g_ProcessCount);
    }
    return found;
}

/* ------------------------------------------------------------------ */
/* Notify callback                                                     */
/* ------------------------------------------------------------------ */

static VOID EsProcessNotify(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    WCHAR detail[512];
    WCHAR pidText[24];
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    UNREFERENCED_PARAMETER(ParentId);

    /* " (PID: 4521)" is appended to every line by hand - no printf. */
    RtlStringCchCopyW(pidText, RTL_NUMBER_OF(pidText), L" (PID: ");
    {
        WCHAR num[12];
        USHORT i = 0;
        ULONG  v = pid;

        /* decimal, max 10 digits */
        if (v == 0) {
            num[i++] = L'0';
        } else {
            WCHAR rev[12];
            USHORT n = 0;
            while (v > 0 && n < 11) {
                rev[n++] = (WCHAR)(L'0' + (v % 10));
                v /= 10;
            }
            while (n > 0) {
                num[i++] = rev[--n];
            }
        }
        num[i] = L'\0';
        RtlStringCchCatW(pidText, RTL_NUMBER_OF(pidText), num);
    }
    RtlStringCchCatW(pidText, RTL_NUMBER_OF(pidText), L")");

    if (CreateInfo != NULL) {
        WCHAR  name[ES_NAME_CCH];
        WCHAR  head[440];
        PCWSTR commandLine = NULL;
        USHORT cmdChars = 0;

        /* ---- process created ---- */
        if (CreateInfo->ImageFileName != NULL) {
            EsGetBaseName(CreateInfo->ImageFileName, name, ES_NAME_CCH);
        } else {
            RtlStringCchCopyW(name, ES_NAME_CCH, L"(unknown)");
        }

        EsRememberProcess(ProcessId, name);

        if (CreateInfo->CommandLine != NULL &&
            CreateInfo->CommandLine->Buffer != NULL &&
            CreateInfo->CommandLine->Length > 0) {

            commandLine = CreateInfo->CommandLine->Buffer;
            cmdChars = CreateInfo->CommandLine->Length / sizeof(WCHAR);
        }

        if (commandLine != NULL) {
            /* Command line already starts with the executable name. */
            USHORT copyChars = cmdChars;

            if (copyChars >= RTL_NUMBER_OF(head)) {
                copyChars = (USHORT)(RTL_NUMBER_OF(head) - 1);
            }
            RtlCopyMemory(head, commandLine, (SIZE_T)copyChars * sizeof(WCHAR));
            head[copyChars] = L'\0';
        } else {
            RtlStringCchCopyW(head, RTL_NUMBER_OF(head), name);
        }

        RtlStringCchCopyW(detail, RTL_NUMBER_OF(detail), head);
        RtlStringCchCatW(detail, RTL_NUMBER_OF(detail), pidText);

        EsLogEvent("Process Created", detail);

    } else {
        WCHAR name[ES_NAME_CCH];

        /* ---- process ended ---- */
        if (!EsForgetProcess(ProcessId, name, ES_NAME_CCH)) {
            RtlStringCchCopyW(name, ES_NAME_CCH, L"(unknown)");
        }

        RtlStringCchCopyW(detail, RTL_NUMBER_OF(detail), name);
        RtlStringCchCatW(detail, RTL_NUMBER_OF(detail), pidText);

        EsLogEvent("Process Ended", detail);
    }
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

NTSTATUS EsProcessInit(VOID)
{
    NTSTATUS status;

    InitializeListHead(&g_ProcessList);
    ExInitializeFastMutex(&g_ProcessLock);
    g_ProcessCount = 0;

    status = PsSetCreateProcessNotifyRoutineEx(EsProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        g_Registered = TRUE;
    }
    return status;
}

VOID EsProcessShutdown(VOID)
{
    if (g_Registered) {
        /* Blocks until in-flight callbacks return. */
        PsSetCreateProcessNotifyRoutineEx(EsProcessNotify, TRUE);
        g_Registered = FALSE;
    }

    /* Free entries of processes that never exited while we ran. */
    for (;;) {
        PES_PROCESS_ENTRY entry;

        ExAcquireFastMutex(&g_ProcessLock);
        if (IsListEmpty(&g_ProcessList)) {
            ExReleaseFastMutex(&g_ProcessLock);
            break;
        }
        entry = CONTAINING_RECORD(g_ProcessList.Flink, ES_PROCESS_ENTRY, ListEntry);
        RemoveEntryList(&entry->ListEntry);
        ExReleaseFastMutex(&g_ProcessLock);

        ExFreePoolWithTag(entry, ES_POOL_TAG);
    }
    g_ProcessCount = 0;
}
