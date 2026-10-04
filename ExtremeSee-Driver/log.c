/*++
 *
 *  ExtremeSee - Log engine
 *
 *  Callbacks call EsLogEvent() which only formats a fixed size record and
 *  appends it to an in-memory queue. A dedicated system thread owns the
 *  file handle and writes the queue contents to C:\ExtremeSee.log with
 *  ZwWriteFile at PASSIVE_LEVEL. No callback ever touches a file, so the
 *  minifilter cannot recurse into itself and nothing can deadlock here.
 *
--*/

#include "ExtremeSee.h"

typedef struct _ES_RECORD {
    LIST_ENTRY ListEntry;
    USHORT     Cch;                          /* characters, excluding NUL */
    WCHAR      Buffer[ES_MAX_RECORD_CCH];
} ES_RECORD, *PES_RECORD;

static LIST_ENTRY    g_Queue;
static FAST_MUTEX    g_QueueLock;
static KEVENT        g_QueueEvent;           /* set when records arrive   */
static KEVENT        g_StopEvent;            /* set to stop the worker    */
static volatile LONG g_QueueCount;
static volatile LONG g_Accepting;
static volatile LONG g_StopRequested;
static PETHREAD      g_WorkerObject;
static HANDLE        g_FileHandle;
static LONGLONG      g_FileOffset;
static BOOLEAN       g_WriteWarned;

/* ------------------------------------------------------------------ */
/* Small formatting helpers (no printf style formatting in kernel)     */
/* ------------------------------------------------------------------ */

static PWCHAR EsPut2(PWCHAR p, ULONG v)
{
    *p++ = (WCHAR)(L'0' + ((v / 10) % 10));
    *p++ = (WCHAR)(L'0' + (v % 10));
    return p;
}

static PWCHAR EsPut4(PWCHAR p, ULONG v)
{
    *p++ = (WCHAR)(L'0' + ((v / 1000) % 10));
    *p++ = (WCHAR)(L'0' + ((v / 100) % 10));
    *p++ = (WCHAR)(L'0' + ((v / 10) % 10));
    *p++ = (WCHAR)(L'0' + (v % 10));
    return p;
}

VOID EsStatusHex(NTSTATUS Status, PWCHAR Out)
{
    static const WCHAR digits[] = L"0123456789ABCDEF";
    ULONG value = (ULONG)Status;
    LONG  i;

    for (i = 7; i >= 0; i--) {
        Out[7 - i] = digits[(value >> (i * 4)) & 0xF];
    }
    Out[8] = L'\0';
}

/* "YYYY-MM-DD HH:MM:SS" - 19 characters, returns pointer past them. */
static PWCHAR EsFormatTimestamp(PWCHAR p)
{
    LARGE_INTEGER systemTime;
    LARGE_INTEGER localTime;
    TIME_FIELDS    fields;

    KeQuerySystemTimePrecise(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    RtlTimeToTimeFields(&localTime, &fields);

    p = EsPut4(p, (ULONG)fields.Year);
    *p++ = L'-';
    p = EsPut2(p, (ULONG)fields.Month);
    *p++ = L'-';
    p = EsPut2(p, (ULONG)fields.Day);
    *p++ = L' ';
    p = EsPut2(p, (ULONG)fields.Hour);
    *p++ = L':';
    p = EsPut2(p, (ULONG)fields.Minute);
    *p++ = L':';
    p = EsPut2(p, (ULONG)fields.Second);
    return p;
}

VOID EsGetBaseName(PCUNICODE_STRING FullPath, PWCHAR Out, SIZE_T OutCch)
{
    USHORT chars;
    USHORT i;
    USHORT len;

    Out[0] = L'\0';

    if (FullPath == NULL || FullPath->Buffer == NULL || FullPath->Length == 0) {
        RtlStringCchCopyW(Out, OutCch, L"(unknown)");
        return;
    }

    chars = FullPath->Length / sizeof(WCHAR);
    i = chars;
    while (i > 0) {
        WCHAR c = FullPath->Buffer[i - 1];
        if (c == L'\\' || c == L'/') {
            break;
        }
        i--;
    }

    len = chars - i;
    if (len == 0) {
        /* Path ends with a separator - fall back to the whole string. */
        i = 0;
        len = chars;
    }
    if ((SIZE_T)len >= OutCch) {
        len = (USHORT)(OutCch - 1);
    }

    RtlCopyMemory(Out, FullPath->Buffer + i, (SIZE_T)len * sizeof(WCHAR));
    Out[len] = L'\0';
}

/* ------------------------------------------------------------------ */
/* File I/O (worker thread only)                                       */
/* ------------------------------------------------------------------ */

static NTSTATUS EsOpenLogFile(VOID)
{
    UNICODE_STRING    path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   iosb;
    FILE_STANDARD_INFORMATION info;
    NTSTATUS          status;

    RtlInitUnicodeString(&path, ES_LOG_PATH);
    InitializeObjectAttributes(&oa,
                               &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = ZwCreateFile(&g_FileHandle,
                          GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                          &oa,
                          &iosb,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          FILE_OPEN_IF,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT,
                          NULL,
                          0);
    if (!NT_SUCCESS(status)) {
        g_FileHandle = NULL;
        return status;
    }

    status = ZwQueryInformationFile(g_FileHandle,
                                    &iosb,
                                    &info,
                                    sizeof(info),
                                    FileStandardInformation);
    g_FileOffset = NT_SUCCESS(status) ? info.EndOfFile.QuadPart : 0;

    /* Fresh (empty) file: write a UTF-16 LE BOM once. */
    if (g_FileOffset == 0) {
        USHORT bom = 0xFEFF;
        LARGE_INTEGER zero;

        zero.QuadPart = 0;
        status = ZwWriteFile(g_FileHandle, NULL, NULL, NULL, &iosb,
                             &bom, sizeof(bom), &zero, NULL);
        if (NT_SUCCESS(status)) {
            g_FileOffset = (LONGLONG)iosb.Information;
        }
    }

    return STATUS_SUCCESS;
}

/* Writes at g_FileOffset. On failure the file is reopened once
 * (handles a log file that malware deleted underneath us). */
static BOOLEAN EsWriteBytes(PVOID Buffer, ULONG Bytes)
{
    IO_STATUS_BLOCK   iosb;
    LARGE_INTEGER     offset;
    NTSTATUS          status;
    BOOLEAN           retried = FALSE;

    if (g_FileHandle == NULL) {
        return FALSE;
    }

retry:
    offset.QuadPart = g_FileOffset;
    status = ZwWriteFile(g_FileHandle, NULL, NULL, NULL, &iosb,
                         Buffer, Bytes, &offset, NULL);
    if (NT_SUCCESS(status)) {
        g_FileOffset += (LONGLONG)iosb.Information;
        return TRUE;
    }

    if (!retried) {
        retried = TRUE;
        if (g_FileHandle != NULL) {
            ZwClose(g_FileHandle);
            g_FileHandle = NULL;
        }
        if (NT_SUCCESS(EsOpenLogFile())) {
            goto retry;
        }
    }

    if (!g_WriteWarned) {
        g_WriteWarned = TRUE;
        DbgPrint("ExtremeSee: log write failed (0x%08x)\n", status);
    }
    return FALSE;
}

static VOID EsWriteToDisk(PES_RECORD Rec)
{
    if (g_FileHandle == NULL) {
        return;
    }
    EsWriteBytes(Rec->Buffer, (ULONG)Rec->Cch * sizeof(WCHAR));
}

/* ------------------------------------------------------------------ */
/* Queue                                                               */
/* ------------------------------------------------------------------ */

static VOID EsDrainQueue(VOID)
{
    LIST_ENTRY local;

    InitializeListHead(&local);

    /* Move the whole queue to a private list in one locked step, then
     * clear the event while still holding the lock so no wakeup can be
     * lost against a producer inserting right after us. */
    ExAcquireFastMutex(&g_QueueLock);
    if (!IsListEmpty(&g_Queue)) {
        local.Flink = g_Queue.Flink;
        local.Blink = g_Queue.Blink;
        g_Queue.Flink->Blink = &local;
        g_Queue.Blink->Flink = &local;
        InitializeListHead(&g_Queue);
    }
    KeClearEvent(&g_QueueEvent);
    ExReleaseFastMutex(&g_QueueLock);

    while (!IsListEmpty(&local)) {
        PES_RECORD rec = CONTAINING_RECORD(local.Flink, ES_RECORD, ListEntry);

        RemoveEntryList(&rec->ListEntry);
        EsWriteToDisk(rec);
        ExFreePoolWithTag(rec, ES_POOL_TAG);
        InterlockedDecrement(&g_QueueCount);
    }
}

VOID EsLogEvent(PCSTR Tag, PCWSTR Detail)
{
    PES_RECORD rec;
    PWCHAR     p;
    PWCHAR     end;
    ULONG      i;

    if (InterlockedCompareExchange(&g_Accepting, 1, 1) != 1) {
        return;
    }

    if (InterlockedIncrement(&g_QueueCount) > ES_MAX_QUEUE_RECORDS) {
        InterlockedDecrement(&g_QueueCount);
        return;                          /* under pressure: drop event */
    }

    rec = (PES_RECORD)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                      sizeof(ES_RECORD),
                                      ES_POOL_TAG);
    if (rec == NULL) {
        InterlockedDecrement(&g_QueueCount);
        return;
    }

    p = rec->Buffer;
    end = rec->Buffer + (ES_MAX_RECORD_CCH - 4);   /* reserve \r\n\0 */

    p = EsFormatTimestamp(p);
    if (p < end) { *p++ = L' '; }
    if (p < end) { *p++ = L'['; }

    if (Tag != NULL) {
        for (i = 0; Tag[i] != '\0' && p < end; i++) {
            *p++ = (WCHAR)(UCHAR)Tag[i];
        }
    }

    if (p < end) { *p++ = L']'; }
    if (p < end) { *p++ = L' '; }

    if (Detail != NULL) {
        while (*Detail != L'\0' && p < end) {
            *p++ = *Detail++;
        }
    }

    *p++ = L'\r';
    *p++ = L'\n';
    *p = L'\0';
    rec->Cch = (USHORT)(p - rec->Buffer);

    ExAcquireFastMutex(&g_QueueLock);
    InsertTailList(&g_Queue, &rec->ListEntry);
    KeSetEvent(&g_QueueEvent, 0, FALSE);
    ExReleaseFastMutex(&g_QueueLock);
}

/* ------------------------------------------------------------------ */
/* Worker thread                                                       */
/* ------------------------------------------------------------------ */

static VOID EsWorkerThread(_In_ PVOID Context)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    status = EsOpenLogFile();
    if (!NT_SUCCESS(status)) {
        DbgPrint("ExtremeSee: cannot open log file (0x%08x)\n", status);
    }

    for (;;) {
        PVOID       objects[2];
        KWAIT_BLOCK waitBlocks[2];
        NTSTATUS    waitStatus;

        objects[0] = &g_QueueEvent;
        objects[1] = &g_StopEvent;

        waitStatus = KeWaitForMultipleObjects(2,
                                              objects,
                                              WaitAny,
                                              Executive,
                                              KernelMode,
                                              FALSE,
                                              NULL,
                                              waitBlocks);
        UNREFERENCED_PARAMETER(waitStatus);

        EsDrainQueue();

        if (InterlockedCompareExchange(&g_StopRequested, 1, 1) == 1) {
            break;
        }
    }

    if (g_FileHandle != NULL) {
        ZwClose(g_FileHandle);
        g_FileHandle = NULL;
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

NTSTATUS EsLogInit(VOID)
{
    NTSTATUS status;
    HANDLE   handle;

    InitializeListHead(&g_Queue);
    ExInitializeFastMutex(&g_QueueLock);
    KeInitializeEvent(&g_QueueEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);

    g_QueueCount      = 0;
    g_StopRequested   = 0;
    g_FileHandle      = NULL;
    g_FileOffset      = 0;
    g_WriteWarned     = FALSE;
    g_WorkerObject    = NULL;
    InterlockedExchange(&g_Accepting, 1);

    status = PsCreateSystemThread(&handle,
                                  GENERIC_ALL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  EsWorkerThread,
                                  NULL);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_Accepting, 0);
        return status;
    }

    status = ObReferenceObjectByHandle(handle,
                                       THREAD_ALL_ACCESS,
                                       *PsThreadType,
                                       KernelMode,
                                       (PVOID *)&g_WorkerObject,
                                       NULL);
    ZwClose(handle);

    if (!NT_SUCCESS(status)) {
        /* Cannot wait for the worker later - ask it to exit now. */
        InterlockedExchange(&g_Accepting, 0);
        InterlockedExchange(&g_StopRequested, 1);
        KeSetEvent(&g_StopEvent, 0, FALSE);
        g_WorkerObject = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

VOID EsLogShutdown(VOID)
{
    LARGE_INTEGER timeout;
    NTSTATUS      status;
    PETHREAD      worker;

    InterlockedExchange(&g_Accepting, 0);

    worker = g_WorkerObject;
    if (worker == NULL) {
        return;
    }

    InterlockedExchange(&g_StopRequested, 1);
    KeSetEvent(&g_StopEvent, 0, FALSE);

    timeout.QuadPart = -((LONGLONG)15 * 10 * 1000 * 1000);   /* 15 s */
    status = KeWaitForSingleObject(worker, Executive, KernelMode, FALSE, &timeout);
    if (status == STATUS_TIMEOUT) {
        /* Worker is stuck; leak the queue on purpose instead of
         * freeing memory it might still touch. */
        DbgPrint("ExtremeSee: worker did not stop in time\n");
        ObDereferenceObject(worker);
        g_WorkerObject = NULL;
        return;
    }

    ObDereferenceObject(worker);
    g_WorkerObject = NULL;

    /* Worker already drained, but free anything that raced in. */
    EsDrainQueue();
}
