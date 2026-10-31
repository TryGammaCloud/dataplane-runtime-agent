//! Additional in-guard deny filter, independent of systemd property merging.
use std::io;

#[cfg(target_arch = "x86_64")]
pub fn install() -> io::Result<()> {
    let statement = |code, value| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    };
    let jump = |value, jt, jf| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k: value,
    };
    let mut filter = vec![
        statement(0x20, 4),
        jump(0xc000003e, 1, 0),
        statement(0x06, 0x80000000),
        statement(0x20, 0),
    ];
    // x32 uses the x86_64 audit architecture with a different syscall-number bit.
    filter.push(libc::sock_filter {
        code: 0x45,
        jt: 0,
        jf: 1,
        k: 0x40000000,
    });
    filter.push(statement(0x06, 0x80000000));
    for number in [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_open_by_handle_at,
    ] {
        filter.push(jump(number as u32, 0, 1));
        filter.push(statement(0x06, 0x00050000 | libc::EPERM as u32));
    }
    // ENOSYS lets libc fall back to clone without allowing clone3 namespace flags.
    filter.push(jump(libc::SYS_clone3 as u32, 0, 1));
    filter.push(statement(0x06, 0x00050000 | libc::ENOSYS as u32));
    filter.push(jump(libc::SYS_clone as u32, 0, 3));
    filter.push(statement(0x20, 16));
    let namespaces = libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET;
    filter.push(libc::sock_filter {
        code: 0x45,
        jt: 0,
        jf: 1,
        k: namespaces as u32,
    });
    filter.push(statement(0x06, 0x00050000 | libc::EPERM as u32));
    filter.push(statement(0x06, 0x7fff0000));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
pub fn install() -> io::Result<()> {
    Err(io::Error::other("unsupported isolation architecture"))
}
