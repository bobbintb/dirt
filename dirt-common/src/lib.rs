#![no_std]

#[cfg(feature = "user")]
use serde::Serialize;

pub const MAX_PATH_SIZE: usize = 4096;
pub const MAX_SHARE_LEN: usize = 256;

pub type ShareName = [u8; MAX_SHARE_LEN];

#[cfg_attr(feature = "user", derive(Serialize))]
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum EventType {
    Unlink,
    Rename,
    Create,
    Modified,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Event {
    pub event: EventType,
    pub src_path: [u8; MAX_PATH_SIZE],
    pub tgt_path: [u8; MAX_PATH_SIZE],
}