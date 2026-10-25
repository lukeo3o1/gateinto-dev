use std::io;
use std::mem::offset_of;
use std::net::SocketAddr;
use std::ptr::null_mut;
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Security::{EqualSid, TOKEN_QUERY};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{Denial, Family, Owners, Row, entries, lookup, v4, v6};
use crate::job::Job;
use crate::token::{Handle, TokenUserInfo};

const LOOKUP_ATTEMPTS: u32 = 5;
const LOOKUP_DELAY: Duration = Duration::from_millis(5);
const TABLE_ATTEMPTS: u32 = 8;

pub(super) struct System {
    own: TokenUserInfo,
    job: Option<Arc<Job>>,
}

impl System {
    pub(super) fn new(job: Option<Arc<Job>>) -> io::Result<Self> {
        Ok(Self {
            own: TokenUserInfo::current()?,
            job,
        })
    }

    fn owner(&self, peer: SocketAddr, local: SocketAddr) -> Result<Option<u32>, Denial> {
        lookup(peer, local, rows)
    }

    fn find(&self, peer: SocketAddr, local: SocketAddr) -> Result<u32, Denial> {
        for attempt in 1..=LOOKUP_ATTEMPTS {
            if let Some(pid) = self.owner(peer, local)? {
                return Ok(pid);
            }
            if attempt < LOOKUP_ATTEMPTS {
                std::thread::sleep(LOOKUP_DELAY);
            }
        }
        Err(Denial::NotFound)
    }
}

impl Owners for System {
    fn check(&self, peer: SocketAddr, local: SocketAddr) -> Result<(), Denial> {
        let lookup = |error: io::Error| Denial::Lookup(error.to_string());
        let pid = self.find(peer, local)?;
        // SAFETY: OpenProcess returns an owned handle or null.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(lookup(io::Error::last_os_error()));
        }
        let process = Handle(process);
        if self.owner(peer, local)? != Some(pid) {
            return Err(Denial::NotFound);
        }
        let mut token = null_mut();
        // SAFETY: process is open with query access; token receives an owned handle.
        if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
            return Err(lookup(io::Error::last_os_error()));
        }
        let user = TokenUserInfo::of(&Handle(token)).map_err(lookup)?;
        // SAFETY: both SIDs point into live TOKEN_USER buffers.
        if unsafe { EqualSid(user.sid(), self.own.sid()) } == 0 {
            return Err(Denial::OtherUser);
        }
        if let Some(job) = &self.job {
            let mut inside = 0;
            // SAFETY: both handles are open and inside is writable.
            if unsafe { IsProcessInJob(process.0, job.handle(), &mut inside) } == 0 {
                return Err(lookup(io::Error::last_os_error()));
            }
            if inside == 0 {
                return Err(Denial::NotInJob);
            }
        }
        Ok(())
    }
}

fn rows(family: Family) -> io::Result<Vec<Row>> {
    match family {
        Family::V4 => {
            let table = table(AF_INET)?;
            // SAFETY: the table holds a MIB_TCPTABLE_OWNER_PID followed by its rows, which are
            // plain integers.
            let rows = unsafe {
                entries::<MIB_TCPROW_OWNER_PID>(&table, offset_of!(MIB_TCPTABLE_OWNER_PID, table))
            }?;
            Ok(rows
                .iter()
                .map(|row| Row {
                    local: v4(row.dwLocalAddr, row.dwLocalPort),
                    remote: v4(row.dwRemoteAddr, row.dwRemotePort),
                    pid: row.dwOwningPid,
                })
                .collect())
        }
        Family::V6 => {
            let table = table(AF_INET6)?;
            // SAFETY: the table holds a MIB_TCP6TABLE_OWNER_PID followed by its rows, which are
            // plain integers and byte arrays.
            let rows = unsafe {
                entries::<MIB_TCP6ROW_OWNER_PID>(&table, offset_of!(MIB_TCP6TABLE_OWNER_PID, table))
            }?;
            Ok(rows
                .iter()
                .map(|row| Row {
                    local: v6(row.ucLocalAddr, row.dwLocalPort),
                    remote: v6(row.ucRemoteAddr, row.dwRemotePort),
                    pid: row.dwOwningPid,
                })
                .collect())
        }
    }
}

fn table(family: u16) -> io::Result<Vec<u64>> {
    let mut size = 0;
    let mut buffer: Vec<u64> = Vec::new();
    for _ in 0..TABLE_ATTEMPTS {
        // SAFETY: buffer is 8-byte aligned and holds size bytes, or is null with size 0.
        let status = unsafe {
            GetExtendedTcpTable(
                if buffer.is_empty() {
                    null_mut()
                } else {
                    buffer.as_mut_ptr().cast()
                },
                &mut size,
                0,
                u32::from(family),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        match status {
            NO_ERROR => return Ok(buffer),
            ERROR_INSUFFICIENT_BUFFER => buffer = vec![0; (size as usize).div_ceil(8)],
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
    Err(io::Error::other("the connection table kept growing"))
}
