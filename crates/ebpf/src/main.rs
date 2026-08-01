#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnEvent {
    pub pid: u32,
    pub af: u16,
    pub port: u16,
    pub addr: [u8; 16],
    pub comm: [u8; 16],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262144, 0);

#[kprobe]
pub fn sock_connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx);
    0
}

fn try_connect(ctx: &ProbeContext) -> Result<(), i64> {
    let sa: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let af = unsafe { bpf_probe_read_kernel::<u16>(sa as *const u16)? };
    let mut ev = ConnEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        af,
        port: 0,
        addr: [0u8; 16],
        comm: bpf_get_current_comm().unwrap_or([0u8; 16]),
    };
    ev.port = u16::from_be(unsafe { bpf_probe_read_kernel::<u16>(sa.add(2) as *const u16)? });
    match af {
        2 => {
            let v4 = unsafe { bpf_probe_read_kernel::<[u8; 4]>(sa.add(4) as *const [u8; 4])? };
            ev.addr[..4].copy_from_slice(&v4);
        }
        10 => {
            ev.addr = unsafe { bpf_probe_read_kernel::<[u8; 16]>(sa.add(8) as *const [u8; 16])? };
        }
        _ => return Ok(()),
    }
    let _ = EVENTS.output(&ev, 0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
