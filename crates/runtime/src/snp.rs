//! Raw Linux SEV-SNP guest evidence acquisition, never local proof verification.
//! ABI follows include/uapi/linux/sev-guest.h; hardware validation remains mandatory.
use sha2::{Digest, Sha512};
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

#[repr(C)]
struct ReportRequest {
    data: [u8; 64],
    vmpl: u32,
    reserved: [u8; 28],
}
#[repr(C)]
struct ReportResponse {
    data: [u8; 4000],
}
#[repr(C)]
struct GuestIoctl {
    version: u8,
    reserved: [u8; 7],
    request: u64,
    response: u64,
    error: u64,
}

pub fn report_data(context: &str) -> [u8; 64] {
    let mut digest = Sha512::new();
    digest.update(b"gammacloud.runtime.snp-evidence.v1\0");
    digest.update(context.as_bytes());
    digest.finalize().into()
}

pub fn collect(context: &str) -> io::Result<String> {
    if context.len() > 8192 {
        return Err(io::Error::other("evidence context too large"));
    }
    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/sev-guest")?;
    if !device.metadata()?.file_type().is_char_device() {
        return Err(io::Error::other("invalid guest device"));
    }
    let mut request = ReportRequest {
        data: report_data(context),
        vmpl: 0,
        reserved: [0; 28],
    };
    let mut response = ReportResponse { data: [0; 4000] };
    let mut ioctl = GuestIoctl {
        version: 1,
        reserved: [0; 7],
        request: (&mut request as *mut ReportRequest) as u64,
        response: (&mut response as *mut ReportResponse) as u64,
        error: 0,
    };
    let command = libc::_IOWR::<GuestIoctl>(b'S' as u32, 0);
    if unsafe { libc::ioctl(device.as_raw_fd(), command, &mut ioctl) } != 0 || ioctl.error != 0 {
        return Err(io::Error::other("SNP report unavailable"));
    }
    // Return the raw firmware response for the independent verifier; do not parse a
    // measurement or claim a valid signature from ioctl success alone.
    Ok(serde_json::json!({"format":"linux-snp-report-response-v1","report_data_hex":crate::authorization::hex(&request.data),"response_hex":crate::authorization::hex(&response.data),"verified":false}).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_abi_layout_and_context_binding() {
        assert_eq!(std::mem::size_of::<ReportRequest>(), 96);
        assert_eq!(std::mem::size_of::<GuestIoctl>(), 32);
        assert_eq!(std::mem::size_of::<ReportResponse>(), 4000);
        assert_ne!(report_data("boot-a"), report_data("boot-b"));
        assert_ne!(report_data("owner-a"), report_data("owner-b"));
    }
}
