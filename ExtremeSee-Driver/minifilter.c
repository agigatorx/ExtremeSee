/*++
 *
 *  ExtremeSee - File create / delete logging (minifilter)
 *
 *  IRP_MJ_CREATE (post)   -> "[File Created]"  when the create disposition
 *                            is FILE_CREATE / FILE_OPEN_IF / FILE_OVERWRITE*
 *  IRP_MJ_SET_INFORMATION (post) -> "[File Deleted]" when a delete
 *                            disposition is set (FileDispositionInformation[Ex])
 *
 *  Callbacks only format a record and enqueue it - no file I/O is done
 *  inside the filter, so there is no recursion and no deadlock path.
 *  The log file itself (ExtremeSee.log) is filtered out by name.
 *
--*/

#include "ExtremeSee.h"

PFLT_FILTER EsFilter = NULL;

static UNICODE_STRING g_LogBaseName;

static FLT_PREOP_CALLBACK_STATUS FLTAPI EsPreCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS FLTAPI EsPostCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static FLT_PREOP_CALLBACK_STATUS FLTAPI EsPreSetInfo(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS FLTAPI EsPostSetInfo(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

/* ------------------------------------------------------------------ */
/* Shared helper: resolve name and enqueue the event                   */
/* ------------------------------------------------------------------ */

static VOID EsLogFileEvent(PCSTR Tag, _In_ PFLT_CALLBACK_DATA Data)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    WCHAR    detail[640];
    WCHAR    pidText[24];
    USHORT   nameChars;
    USHORT   budget;
    ULONG    pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_OPENED,
                                           &nameInfo);
    }
    if (!NT_SUCCESS(status)) {
        return;
    }

    FltParseFileNameInformation(nameInfo);

    /* Never log our own log file. */
    if (nameInfo->FinalComponent.Buffer != NULL &&
        nameInfo->FinalComponent.Length > 0 &&
        RtlEqualUnicodeString(&nameInfo->FinalComponent, &g_LogBaseName, TRUE)) {
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    /* detail = full path (truncated) */
    nameChars = nameInfo->Name.Length / sizeof(WCHAR);
    budget = (USHORT)RTL_NUMBER_OF(detail) - 32;   /* room for " (PID: n)" */
    if (nameChars > budget) {
        nameChars = budget;
    }
    RtlCopyMemory(detail, nameInfo->Name.Buffer, (SIZE_T)nameChars * sizeof(WCHAR));
    detail[nameChars] = L'\0';

    FltReleaseFileNameInformation(nameInfo);

    /* append " (PID: n)" without printf */
    RtlStringCchCopyW(pidText, RTL_NUMBER_OF(pidText), L" (PID: ");
    {
        WCHAR num[12];
        USHORT i = 0;
        ULONG  v = pid;

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

    RtlStringCchCatW(detail, RTL_NUMBER_OF(detail), pidText);

    EsLogEvent(Tag, detail);
}

/* ------------------------------------------------------------------ */
/* IRP_MJ_CREATE                                                       */
/* ------------------------------------------------------------------ */

static FLT_PREOP_CALLBACK_STATUS FLTAPI EsPreCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);

    *CompletionContext = NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI EsPostCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    ULONG options;
    ULONG disposition;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (Data->Iopb->IrpFlags & (IRP_PAGING_IO | IRP_NOCACHE)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    options = Data->Iopb->Parameters.Create.Options;
    disposition = (options >> 24) & 0xFF;    /* create disposition lives in the high byte */

    /* Log only create-intent opens, not plain reads of existing files. */
    if (disposition != FILE_OPEN) {
        EsLogFileEvent("File Created", Data);
    }

    /* Rare, but malware does use FILE_DELETE_ON_CLOSE. */
    if (options & FILE_DELETE_ON_CLOSE) {
        EsLogFileEvent("File Deleted", Data);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ------------------------------------------------------------------ */
/* IRP_MJ_SET_INFORMATION (deletes)                                    */
/* ------------------------------------------------------------------ */

static FLT_PREOP_CALLBACK_STATUS FLTAPI EsPreSetInfo(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);

    *CompletionContext = NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI EsPostSetInfo(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    FILE_INFORMATION_CLASS infoClass;
    PVOID                   infoBuffer;
    BOOLEAN                 deleted = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (Data->Iopb->IrpFlags & IRP_PAGING_IO) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    infoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    if (infoClass == FileDispositionInformation) {
        deleted = ((PFILE_DISPOSITION_INFORMATION)infoBuffer)->DeleteFile;
    } else if (infoClass == FileDispositionInformationEx) {
        ULONG flags = ((PFILE_DISPOSITION_INFORMATION_EX)infoBuffer)->Flags;
        deleted = (flags & FILE_DISPOSITION_DELETE) != 0;
    } else {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (deleted) {
        EsLogFileEvent("File Deleted", Data);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

static const FLT_OPERATION_REGISTRATION EsCallbacks[] = {
    { IRP_MJ_CREATE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      EsPreCreate,
      EsPostCreate },

    { IRP_MJ_SET_INFORMATION,
      0,
      EsPreSetInfo,
      EsPostSetInfo },

    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION EsFltRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                                  /* flags */
    NULL,                               /* context */
    EsCallbacks,
    NULL                                /* remaining callbacks unused */
};

NTSTATUS EsFileInit(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    RtlInitUnicodeString(&g_LogBaseName, ES_LOG_BASENAME);

    status = FltRegisterFilter(DriverObject, &EsFltRegistration, &EsFilter);
    if (!NT_SUCCESS(status)) {
        EsFilter = NULL;
        return status;
    }

    /*
     * If the minifilter altitude keys are missing (driver started with a
     * plain "sc create" instead of install.cmd) this fails; the filter
     * stays registered and is released by EsFileShutdown().
     */
    status = FltStartFiltering(EsFilter);
    return status;
}

VOID EsFileShutdown(VOID)
{
    if (EsFilter != NULL) {
        /* Blocks until all outstanding operations have completed. */
        FltUnregisterFilter(EsFilter);
        EsFilter = NULL;
    }
}
