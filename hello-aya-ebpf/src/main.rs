#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, IpProto};
use network_types::icmp::{IcmpHdr, IcmpHdrEcho};

const ICMP_TYPE_ECHO_REQUEST: u8 = 8;

#[xdp]
pub fn hello_aya(ctx: XdpContext) -> u32 {
    match try_hello_aya(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_hello_aya(ctx: XdpContext) -> Result<u32, ()> {
    let mut cursor = 0usize;

    // eth -> ip
    let ethhdr: *const EthHdr = ptr_at(&ctx, cursor)?; 
    cursor += EthHdr::LEN;
    if unsafe {(*ethhdr).ether_type} != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS)
    }

    // ip -> icmp
    let iphdr: *const Ipv4Hdr = ptr_at(&ctx, cursor)?;
    cursor += Ipv4Hdr::LEN;
    if unsafe {(*iphdr).proto} != IpProto::Icmp {
        return Ok(xdp_action::XDP_PASS)
    }

    // icmp -> echo request
    let icmphdr: *const IcmpHdr = ptr_at(&ctx, cursor)?;
    cursor += IcmpHdr::LEN;
    if unsafe {(*icmphdr).type_} != ICMP_TYPE_ECHO_REQUEST {
        return Ok(xdp_action::XDP_PASS)
    }

    info!(&ctx, "received an icmp echo request");
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
