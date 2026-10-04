/*++
 *
 *  ExtremeSee - Kernel Monitor Driver
 *
 *  Malware analysis helper: captures process creation/termination and
 *  file create/delete events from kernel mode and writes them to
 *  C:\ExtremeSee.log.
 *
 *  Design rules (to stay BSOD-free):
 *    - Only documented, supported callback APIs are used:
 *        PsSetCreateProcessNotifyRoutineEx  (process events)
 *        FltRegisterFilter / FltStartFiltering (file events, minifilter)
 *    - Callbacks never do file I/O. They only format a fixed size record
 *      and push it onto a queue.
 *    - A dedicated system thread drains the queue and performs all
 *      ZwWriteFile calls at PASSIVE_LEVEL.
 *    - Unload path unregisters every callback before stopping the writer,
 *      so no callback can run on freed memory.
 *
--*/

#pragma once

/* fltKernel.h pulls in ntifs.h; including ntddk.h as well would
 * redefine PEPROCESS/PETHREAD (C2371). */
#include <fltKernel.h>
#include <ntstrsafe.h>

/* Pool tag (shows up as "Xsee" in pool tools) */
#define ES_POOL_TAG                 'eSXE'

/* Log file (NT object path) */
#define ES_LOG_PATH                 L"\\??\\C:\\ExtremeSee.log"
#define ES_LOG_BASENAME             L"ExtremeSee.log"

/* Max length of one log record in WCHARs (including \r\n\0) */
#define ES_MAX_RECORD_CCH           768

/* Max queued records; further events are dropped (never bugcheck) */
#define ES_MAX_QUEUE_RECORDS        4096

/* Process name buffer size */
#define ES_NAME_CCH                 64

/* Max number of tracked processes (name lookup for [Process Ended]) */
#define ES_MAX_TRACKED_PROCESSES    4096

/* ---- log.c ---- */
NTSTATUS EsLogInit(VOID);
VOID     EsLogShutdown(VOID);

/* Formats "<timestamp> [<Tag>] <Detail>\r\n" and enqueues it. */
VOID     EsLogEvent(PCSTR Tag, PCWSTR Detail);

/* Copies the last path component of a full NT path into Out. */
VOID     EsGetBaseName(PCUNICODE_STRING FullPath, PWCHAR Out, SIZE_T OutCch);

/* Renders an NTSTATUS as "0x12345678" (9 WCHARs incl. terminator). */
VOID     EsStatusHex(NTSTATUS Status, PWCHAR Out);

/* ---- process.c ---- */
NTSTATUS EsProcessInit(VOID);
VOID     EsProcessShutdown(VOID);

/* ---- minifilter.c ---- */
NTSTATUS EsFileInit(PDRIVER_OBJECT DriverObject);
VOID     EsFileShutdown(VOID);

extern PFLT_FILTER EsFilter;
