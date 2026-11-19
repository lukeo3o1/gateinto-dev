use std::io;
use std::net::Ipv4Addr;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IpDadStateDeprecated as IP_DAD_STATE_DEPRECATED,
    IpDadStateDuplicate as IP_DAD_STATE_DUPLICATE, IpDadStatePreferred as IP_DAD_STATE_PREFERRED,
    IpDadStateTentative as IP_DAD_STATE_TENTATIVE,
};

use super::DadState;

pub(super) fn addresses() -> io::Result<Vec<(Ipv4Addr, DadState)>> {
    let mut table = null_mut();
    // SAFETY: table receives a table allocated by the call, which Table frees with FreeMibTable.
    let status = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
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

fn address(row: &MIB_UNICASTIPADDRESS_ROW) -> Option<(Ipv4Addr, DadState)> {
    // SAFETY: si_family overlays the family field of every variant, and the IPv4 variant is read
    // only when it is AF_INET.
    let bytes = unsafe {
        if row.Address.si_family != AF_INET {
            return None;
        }
        row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()
    };
    let state = match row.DadState {
        IP_DAD_STATE_PREFERRED => DadState::Preferred,
        IP_DAD_STATE_DEPRECATED => DadState::Deprecated,
        IP_DAD_STATE_TENTATIVE => DadState::Tentative,
        IP_DAD_STATE_DUPLICATE => DadState::Duplicate,
        _ => DadState::Invalid,
    };
    Some((Ipv4Addr::from(bytes), state))
}
