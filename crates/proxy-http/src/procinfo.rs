//! 按本地 TCP 端口反查发起连接的进程（PID + 进程名），用于会话列表「进程」列。
//!
//! 客户端经本机 loopback 连到代理，代理据源端口在系统 TCP 表里找到属主 PID，
//! 再用 PID 查进程名。仅 Windows 实现；其它平台返回 `None`（不影响抓包）。

/// 返回 `(pid, 进程名)`，查不到（如远程客户端、连接已关闭）时为 `None`。
#[cfg(windows)]
pub fn resolve_by_local_port(local_port: u16) -> Option<(u32, String)> {
    let pid = win::owning_pid(local_port)?;
    Some((pid, win::process_name(pid).unwrap_or_default()))
}

#[cfg(not(windows))]
pub fn resolve_by_local_port(_local_port: u16) -> Option<(u32, String)> {
    None
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn resolves_own_process() {
        // 自连一个本地监听端口，用客户端源端口反查，应得到本进程 PID。
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (_srv, _peer) = listener.accept().unwrap();
        let local_port = client.local_addr().unwrap().port();

        let (pid, name) = resolve_by_local_port(local_port).expect("应能反查到属主进程");
        assert_eq!(pid, std::process::id());
        assert!(!name.is_empty(), "进程名不应为空");
    }
}

#[cfg(windows)]
mod win {
    use std::os::raw::{c_ulong, c_void};

    #[repr(C)]
    struct MibTcpRowOwnerPid {
        state: u32,
        local_addr: u32,
        local_port: u32,
        remote_addr: u32,
        remote_port: u32,
        owning_pid: u32,
    }
    #[repr(C)]
    struct MibTcpTableOwnerPid {
        num_entries: u32,
        table: [MibTcpRowOwnerPid; 1], // 变长数组，实际长度 num_entries
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            p_tcp_table: *mut c_void,
            pdw_size: *mut c_ulong,
            b_order: i32,
            ul_af: c_ulong,
            table_class: c_ulong,
            reserved: c_ulong,
        ) -> c_ulong;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn QueryFullProcessImageNameW(h: *mut c_void, flags: u32, buf: *mut u16, size: *mut u32) -> i32;
    }

    const AF_INET: c_ulong = 2;
    const TCP_TABLE_OWNER_PID_ALL: c_ulong = 5;
    const NO_ERROR: c_ulong = 0;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    /// 在 IPv4 TCP 表里找 `local_port` 对应的属主 PID。
    pub fn owning_pid(local_port: u16) -> Option<u32> {
        unsafe {
            let mut size: c_ulong = 0;
            // 先取所需缓冲区大小。
            GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if size == 0 {
                return None;
            }
            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut c_void, &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0,
            );
            if ret != NO_ERROR {
                return None;
            }
            let table = &*(buf.as_ptr() as *const MibTcpTableOwnerPid);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.num_entries as usize);
            for row in rows {
                // local_port 低 16 位为网络字节序，转成主机序比较。
                let port = ((row.local_port & 0xffff) as u16).swap_bytes();
                if port == local_port {
                    return Some(row.owning_pid);
                }
            }
            None
        }
    }

    /// PID → 可执行文件名（basename）。
    pub fn process_name(pid: u32) -> Option<String> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 260];
            let mut size = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
            CloseHandle(h);
            if ok == 0 {
                return None;
            }
            let path = String::from_utf16_lossy(&buf[..size as usize]);
            Some(path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string())
        }
    }
}
