use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

pub(super) fn addresses() -> io::Result<Vec<IpAddr>> {
    let mut table = null_mut();
    // SAFETY: table receives a table allocated by the call, which Table frees with FreeMibTable.
    let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
    if status != NO_ERROR {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if table.is_null() {
        return Err(io::Error::other("the address table is missing"));
    }
    Ok(Table(table).rows().iter().filter_map(address).collect())
}

struct Table(*mut MIB_UNICASTIPADDRESS_TABLE);

impl Table {
    fn rows(&self) -> &[MIB_UNICASTIPADDRESS_ROW] {
        // SAFETY: the table is live until FreeMibTable and holds NumEntries rows from its Table field
        // on; the pointer to them is taken without a reference to the one-row array type.
        unsafe {
            let count = (*self.0).NumEntries as usize;
            let rows = (&raw const (*self.0).Table).cast::<MIB_UNICASTIPADDRESS_ROW>();
            std::slice::from_raw_parts(rows, count)
        }
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        // SAFETY: the table came from GetUnicastIpAddressTable and is freed once.
        unsafe { FreeMibTable(self.0.cast()) };
    }
}

fn address(row: &MIB_UNICASTIPADDRESS_ROW) -> Option<IpAddr> {
    // SAFETY: si_family overlays the family field of both variants, and it selects the variant read.
    unsafe {
        match row.Address.si_family {
            AF_INET => {
                let bytes = row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                Some(Ipv4Addr::from(bytes).into())
            }
            AF_INET6 => Some(Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte).into()),
            _ => None,
        }
    }
}
