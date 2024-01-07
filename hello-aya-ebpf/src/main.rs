#![no_std]
#![no_main]

use aya_bpf::helpers::bpf_csum_diff;
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, IpProto};
use network_types::icmp::IcmpHdr;

const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
const ICMP_TYPE_ECHO_REPLY: u8 = 0;

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
    let ethhdr: *mut EthHdr = mut_ptr_at(&ctx, cursor)?; 
    cursor += EthHdr::LEN;
    if unsafe {(*ethhdr).ether_type} != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS)
    }

    // ip -> icmp
    let iphdr: *mut Ipv4Hdr = mut_ptr_at(&ctx, cursor)?;
    cursor += Ipv4Hdr::LEN;
    if unsafe {(*iphdr).proto} != IpProto::Icmp {
        return Ok(xdp_action::XDP_PASS)
    }

    // icmp -> echo request
    let icmphdr: *mut IcmpHdr = mut_ptr_at(&ctx, cursor)?;
    cursor += IcmpHdr::LEN;
    if unsafe {(*icmphdr).type_} != ICMP_TYPE_ECHO_REQUEST {
        return Ok(xdp_action::XDP_PASS)
    }
    let icmp_echo_req = unsafe { (*icmphdr).un.echo };

    // log packet contents
    let orig_ip_src_addr = unsafe { (*iphdr).src_addr };
    let orig_ip_src_addr_native_endian = u32::from_be(orig_ip_src_addr);
    info!(
        &ctx,
        "received an icmp echo request src={}.{}.{}.{} ihl={} len={} ttl={} id={} seq={}",
        (orig_ip_src_addr_native_endian >> 24) & 0xff,
        (orig_ip_src_addr_native_endian >> 16) & 0xff,
        (orig_ip_src_addr_native_endian >> 8) & 0xff,
        (orig_ip_src_addr_native_endian >> 0) & 0xff,
        unsafe { (*iphdr).ihl() },
        u16::from_be(unsafe { (*iphdr).tot_len }),
        unsafe { (*iphdr).ttl },
        u16::from_be(icmp_echo_req.id),
        u16::from_be(icmp_echo_req.sequence),
    );

    // update icmp
    unsafe {
        let orig_csum = (*icmphdr).checksum;
        (*icmphdr).checksum = 0;

        // calculate checksum after clearing the current icmp type field
        let new_csum = fold_checksum(
            bpf_csum_diff(
                    icmphdr as *mut u32, 4, 
                    0 as *mut u32, 0,
                    !orig_csum as u32
                )
        );

        (*icmphdr).type_ = ICMP_TYPE_ECHO_REPLY; // == 0
        (*icmphdr).checksum = new_csum;
    }

    // update ip
    unsafe {
        let orig_src_addr = (*iphdr).src_addr;
        (*iphdr).src_addr = (*iphdr).dst_addr;
        (*iphdr).dst_addr = orig_src_addr;
    }

    // update eth
    unsafe {
        let orig_src_addr = (*ethhdr).src_addr;
        (*ethhdr).src_addr = (*ethhdr).dst_addr;
        (*ethhdr).dst_addr = orig_src_addr;
    }

    info!(&ctx, "sending an echo reply");

    Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

/// bound-checked pointer
/// see https://aya-rs.dev/book/start/parsing-packets/#starting-out
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

#[inline(always)]
fn mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    Ok(ptr_at::<T>(ctx, offset)? as *mut T)
}

/// folds i64 intermediate checksum into u16 one's complement
#[inline(always)]
fn fold_checksum(sum: i64) -> u16 {
    let mut csum = sum;
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return !csum as u16;
}
