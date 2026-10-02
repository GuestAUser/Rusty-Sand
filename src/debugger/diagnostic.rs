use super::{
    Amd64Registers, DebugCounters, DebugString, ExceptionDetails, ImagePath, MemoryEvidence,
    MAX_DEBUG_STRING_BYTES, MAX_IMAGE_PATH_UNITS, MAX_INSTRUCTION_BYTES,
};
use crate::sandbox::process::ProcessHandle;
use crate::sandbox::resource::{with_cleanup, OwnedHandle};
use anyhow::{bail, Context, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, FILE_NAME_OPENED, GETFINALPATHNAMEBYHANDLE_FLAGS, VOLUME_NAME_DOS,
};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, ReadProcessMemory, CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64,
    EXCEPTION_DEBUG_INFO, OUTPUT_DEBUG_STRING_INFO,
};
use windows::Win32::System::Threading::{
    GetProcessIdOfThread, OpenThread, THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION,
};

pub(super) fn image_path(file: HANDLE, counters: &mut DebugCounters) -> ImagePath {
    if file.is_invalid() {
        counters.unavailable_image_paths = counters.unavailable_image_paths.saturating_add(1);
        return ImagePath::MissingHandle;
    }

    let mut buffer = [0_u16; MAX_IMAGE_PATH_UNITS];
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_OPENED.0 | VOLUME_NAME_DOS.0);

    /*
     * SAFETY: Session lends the still-live debug file handle and does not close
     * it until recording returns. The initialized buffer is writable and the
     * generated binding passes its exact capacity. Windows validates the handle.
     * FILE_NAME_OPENED avoids an additional normalized-path resolution.
     */
    let length = unsafe { GetFinalPathNameByHandleW(file, &mut buffer, flags) };

    if length == 0 {
        /*
         * Capture the raw thread-local error immediately, before any further
         * Windows call. Preserve its DWORD bits without an HRESULT conversion;
         * a missing raw code remains explicit rather than becoming a default.
         */
        let win32_error = std::io::Error::last_os_error()
            .raw_os_error()
            .map(|code| code as u32);
        counters.unavailable_image_paths = counters.unavailable_image_paths.saturating_add(1);

        return ImagePath::Unavailable { win32_error };
    }

    if length as usize >= buffer.len() {
        counters.truncated_image_paths = counters.truncated_image_paths.saturating_add(1);

        /*
         * Windows returns the required capacity, including the terminator, when
         * the supplied buffer is insufficient. Do not retry with target-sized
         * allocation or treat an unspecified partial buffer as a valid path.
         */
        return ImagePath::Truncated {
            required_buffer_units: length,
        };
    }

    let units = &buffer[..length as usize];
    let (path, lossy) = match String::from_utf16(units) {
        Ok(path) => (path, false),
        Err(_) => (String::from_utf16_lossy(units), true),
    };

    ImagePath::Available { path, lossy }
}

pub(super) fn debug_string(
    process: &ProcessHandle,
    string: OUTPUT_DEBUG_STRING_INFO,
    counters: &mut DebugCounters,
) -> DebugString {
    let unicode = string.fUnicode != 0;
    /*
     * Windows supplies the low 16 bits of a byte count for both encodings.
     * Never double the Unicode count or probe beyond this bounded declaration.
     */
    let declared_bytes = usize::from(string.nDebugStringLength);
    let requested = declared_bytes.min(MAX_DEBUG_STRING_BYTES);
    let memory = read_memory(
        process,
        string.lpDebugStringData.0 as usize as u64,
        requested,
    );
    if memory.error.is_some() {
        counters.incomplete_memory_reads = counters.incomplete_memory_reads.saturating_add(1);
    }

    /*
     * Decode only through the first complete terminator. An incomplete UTF-16
     * unit is not text, but remains in memory.bytes along with any trailing
     * bytes. A missing terminator means completeness cannot be established,
     * including when the native 16-bit byte count has wrapped.
     */
    let (text, terminated) = if unicode {
        let pairs = memory.bytes.as_chunks::<2>().0;
        let units: Vec<u16> = pairs
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .take_while(|unit| *unit != 0)
            .collect();

        (String::from_utf16_lossy(&units), units.len() < pairs.len())
    } else {
        let terminator = memory.bytes.iter().position(|byte| *byte == 0);
        let end = terminator.unwrap_or(memory.bytes.len());

        (
            String::from_utf8_lossy(&memory.bytes[..end]).into_owned(),
            terminator.is_some(),
        )
    };

    let truncated =
        declared_bytes > requested || memory.bytes.len() != declared_bytes || !terminated;

    if truncated {
        counters.truncated_debug_strings = counters.truncated_debug_strings.saturating_add(1);
    }

    DebugString {
        unicode,
        declared_units: string.nDebugStringLength,
        text,
        truncated,
        memory,
    }
}

pub(super) fn exception_details(
    process: &ProcessHandle,
    thread_id: u32,
    exception: EXCEPTION_DEBUG_INFO,
    initialization_breakpoint: bool,
    counters: &mut DebugCounters,
) -> ExceptionDetails {
    let record = exception.ExceptionRecord;
    let count = (record.NumberParameters as usize).min(record.ExceptionInformation.len());

    if count < record.NumberParameters as usize {
        counters.truncated_exception_parameters =
            counters.truncated_exception_parameters.saturating_add(1);
    }

    let (context, context_error) = match thread_context(process, thread_id) {
        Ok(context) => (Some(context), None),
        Err(error) => {
            counters.unavailable_contexts = counters.unavailable_contexts.saturating_add(1);
            (None, Some(format!("{error:#}")))
        }
    };

    let address = record.ExceptionAddress as usize as u64;
    let instruction_address = context.as_ref().map_or(address, |context| context.rip);
    let instruction_bytes = read_memory(process, instruction_address, MAX_INSTRUCTION_BYTES);

    if instruction_bytes.error.is_some() {
        counters.incomplete_memory_reads = counters.incomplete_memory_reads.saturating_add(1);
    }

    ExceptionDetails {
        code: record.ExceptionCode.0 as u32,
        flags: record.ExceptionFlags,
        address,
        first_chance: exception.dwFirstChance != 0,
        initialization_breakpoint,
        declared_parameter_count: record.NumberParameters,
        parameters: record.ExceptionInformation[..count]
            .iter()
            .map(|value| *value as u64)
            .collect(),
        context,
        context_error,
        instruction_bytes,
    }
}

pub(super) fn read_memory(
    process: &ProcessHandle,
    address: u64,
    requested: usize,
) -> MemoryEvidence {
    let mut bytes = vec![0; requested];
    let mut read = 0;

    let result = if requested == 0 {
        Ok(())
    } else {
        /*
         * SAFETY: Only the owned process is read. The caller supplies one of the
         * fixed diagnostic bounds, the output buffer has that size, and Windows
         * validates the remote address. No target memory is written or executed.
         */
        unsafe {
            ReadProcessMemory(
                process.process_handle,
                address as usize as *const std::ffi::c_void,
                bytes.as_mut_ptr().cast(),
                requested,
                Some(&mut read),
            )
        }
    };

    bytes.truncate(read.min(requested));
    let error = match result {
        Err(error) => Some(format!("ReadProcessMemory: {error}")),
        Ok(()) if read != requested => Some("ReadProcessMemory returned a short read".into()),
        Ok(()) => None,
    };

    MemoryEvidence {
        address,
        requested_bytes: requested as u32,
        bytes,
        error,
    }
}

fn thread_context(process: &ProcessHandle, thread_id: u32) -> Result<Amd64Registers> {
    /*
     * SAFETY: The thread ID came from a pending event for the owned process.
     * A separate handle is opened so automatic debugger handle ownership is
     * untouched. Its process identity is checked before any context read.
     */
    let mut thread = OwnedHandle::new(
        unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                false,
                thread_id,
            )
        }
        .context("open owned exception thread for context")?,
    );

    let result = (|| {
        /* SAFETY: This is the independently owned thread handle opened above. */
        let owner = unsafe { GetProcessIdOfThread(thread.raw()) };

        if owner == 0 {
            return Err(windows::core::Error::from_win32())
                .context("query exception thread ownership");
        }

        if owner != process.process_id {
            bail!("exception thread does not belong to the owned target");
        }

        /*
         * The generated CONTEXT type is repr(C); explicitly provide the 16-byte
         * AMD64 alignment required by GetThreadContext. Debug-event suspension
         * keeps the context stable until ContinueDebugEvent.
         */
        #[repr(C, align(16))]
        struct AlignedContext(CONTEXT);

        let mut context = AlignedContext(CONTEXT {
            ContextFlags: CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
            ..Default::default()
        });

        /* SAFETY: The aligned output is writable and the owned thread is stopped. */
        unsafe { GetThreadContext(thread.raw(), &mut context.0) }
            .context("read owned exception thread context")?;

        let context = context.0;

        Ok(Amd64Registers {
            rip: context.Rip,
            rsp: context.Rsp,
            rbp: context.Rbp,
            eflags: context.EFlags,
            rax: context.Rax,
            rbx: context.Rbx,
            rcx: context.Rcx,
            rdx: context.Rdx,
            rsi: context.Rsi,
            rdi: context.Rdi,
            r8: context.R8,
            r9: context.R9,
            r10: context.R10,
            r11: context.R11,
            r12: context.R12,
            r13: context.R13,
            r14: context.R14,
            r15: context.R15,
        })
    })();

    with_cleanup(result, thread.close())
}
