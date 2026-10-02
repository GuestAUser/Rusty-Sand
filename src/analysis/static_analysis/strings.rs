use super::model::*;

pub(super) fn extract(bytes: &[u8]) -> (Vec<ExtractedString>, bool) {
    let scanned = &bytes[..bytes.len().min(MAX_STRING_SCAN_BYTES)];
    let mut strings = Vec::new();
    let mut truncated = bytes.len() > scanned.len();

    /*
     * Separate alignments retain UTF-16LE strings at odd file offsets.
     * Limiting code points to printable ASCII avoids interpreting arbitrary
     * pairs of binary bytes as long runs of unrelated Unicode characters.
     */
    for (start, stride, encoding) in [
        (0, 1, StringEncoding::Ascii),
        (0, 2, StringEncoding::Utf16Le),
        (1, 2, StringEncoding::Utf16Le),
    ] {
        if !extract_pass(
            scanned,
            start,
            stride,
            encoding,
            &mut strings,
            &mut truncated,
        ) {
            break;
        }
    }

    strings.sort_by_key(|string| string.offset);

    (strings, truncated)
}

fn printable(bytes: &[u8], offset: usize, stride: usize) -> bool {
    bytes
        .get(offset)
        .is_some_and(|byte| (0x20..=0x7e).contains(byte))
        && (stride == 1 || bytes.get(offset + 1) == Some(&0))
}

fn extract_pass(
    bytes: &[u8],
    start: usize,
    stride: usize,
    encoding: StringEncoding,
    strings: &mut Vec<ExtractedString>,
    truncated: &mut bool,
) -> bool {
    let mut offset = start;

    while offset < bytes.len() {
        if !printable(bytes, offset, stride) {
            offset += stride;
            continue;
        }

        let run_start = offset;

        while printable(bytes, offset, stride) {
            offset += stride;
        }

        let chars = (offset - run_start) / stride;

        if chars < MIN_STRING_CHARS {
            continue;
        }

        if strings.len() == MAX_STRINGS {
            *truncated = true;
            return false;
        }

        let kept = chars.min(MAX_STRING_CHARS);
        let value = (0..kept)
            .map(|index| char::from(bytes[run_start + index * stride]))
            .collect();
        let run_truncated = chars > kept;

        *truncated |= run_truncated;
        strings.push(ExtractedString {
            offset: run_start as u64,
            byte_length: (offset - run_start) as u64,
            encoding,
            value,
            truncated: run_truncated,
        });
    }

    true
}
