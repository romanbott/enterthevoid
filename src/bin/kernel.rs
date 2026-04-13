use clap::Parser;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    vulnerable: bool,
    #[arg(long)]
    allow_page_zero: bool,
}

struct PageTableEntry {
    physical_frame: usize,
    valid: bool,
}

struct MMU {
    arena: Vec<u8>, // 64 KB de "RAM Física"
    page_table: HashMap<usize, PageTableEntry>,
}

impl MMU {
    fn new() -> Self {
        Self {
            arena: vec![0; 64 * 1024],
            page_table: HashMap::new(),
        }
    }

    fn translate(&self, logical_addr: usize) -> Option<usize> {
        let page_num = logical_addr / 4096;
        let offset = logical_addr % 4096;

        match self.page_table.get(&page_num) {
            Some(entry) if entry.valid => {
                let phys_addr = entry.physical_frame + offset;

                let value = self.arena.get(phys_addr).cloned().unwrap_or(0);

                println!(
                    " [KERNEL] MMU Read: Logic addr 0x{:X} -> Physical addr 0x{:X} (Value : 0x{:02X})",
                    logical_addr, phys_addr, value
                );

                Some(phys_addr)
            }
            _ => {
                println!(
                    " [KERNEL] MMU Error: Page Fault at Logic addr 0x{:X} (Not Mapped)",
                    logical_addr
                );
                None
            }
        }
    }
}

struct KernelState {
    mmu: MMU,
    user_privileged: bool,
    user_name: String,
}

fn main() {
    let args = Args::parse();
    let socket_path = "/tmp/rust_os_sim.sock";
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path).unwrap();
    println!(" [KERNEL] Waiting for user login...");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                handle_client(&mut stream, &args);
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}

fn handle_client(stream: &mut UnixStream, args: &Args) {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).unwrap();
    let name = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

    let mut state = KernelState {
        mmu: MMU::new(),
        user_privileged: false,
        user_name: name,
    };

    println!(
        " [KERNEL] User {} (root: {}) connected",
        state.user_name, state.user_privileged
    );

    loop {
        let n = match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let request = String::from_utf8_lossy(&buffer[..n]);
        let cmd: Vec<&str> = request.split_whitespace().collect();
        if cmd.is_empty() {
            continue;
        }

        match cmd[0] {
            "WRITE_LOGICAL" => {
                if let (Some(addr_str), Some(val_str)) = (cmd.get(1), cmd.get(2)) {
                    let logical_addr: usize = addr_str.parse().unwrap_or(0);

                    let value: u8 = if let Some(hex_val) = val_str.strip_prefix("0x") {
                        u8::from_str_radix(hex_val, 16).unwrap_or(0)
                    } else {
                        val_str.parse().unwrap_or(0)
                    };

                    if let Some(phys_addr) = state.mmu.translate(logical_addr) {
                        state.mmu.arena[phys_addr] = value;
                        let _ = stream.write_all(b"OK: Write Successful");
                    } else {
                        let _ = stream.write_all(b"ERROR: Page Fault on Write");
                    }
                }
            }
            "READ_LOGICAL" => {
                if let Some(addr_str) = cmd.get(1) {
                    let logical_addr: usize = addr_str.parse().unwrap_or(0);

                    if let Some(phys_addr) = state.mmu.translate(logical_addr) {
                        let value = state.mmu.arena[phys_addr];

                        let respuesta = format!("VALUE: 0x{:02X}\n", value);
                        let _ = stream.write_all(respuesta.as_bytes());
                    } else {
                        let _ = stream.write_all(b"ERROR: Page Fault on Read\n");
                    }
                }
            }

            "MMAP_LOGICAL" => {
                let addr: usize = cmd[1].parse().unwrap();
                let page_num = addr / 4096;

                if addr == 0 && !args.allow_page_zero {
                    let _ =
                        stream.write_all(b"ERROR: Security Policy - Page Zero mapping forbidden");
                } else {
                    state.mmu.page_table.insert(
                        page_num,
                        PageTableEntry {
                            physical_frame: page_num * 4096,
                            valid: true,
                        },
                    );
                    println!(" [KERNEL] MMU: Page {} mapped.", page_num);
                    let _ = stream.write_all(b"OK: Mapped");
                }
            }

            "MAKE_ROOT" => {
                if state.user_privileged {
                    println!(
                        " [KERNEL] User {} already has root privilegs.",
                        state.user_name
                    );
                    let _ = stream.write_all(b"OK: You are root.\n");
                } else {
                    println!(
                        " [SECURITY_ALERT] Unautorized privilege escalation attempt via MAKE_ROOT by user: {}",
                        state.user_name
                    );
                    let _ = stream.write_all(b"ERROR: Unauthorized. (PSW.mode == 0)\n");
                }
            }

            "SYS_VULN" => {
                if args.vulnerable {
                    if let Some(phys_addr) = state.mmu.translate(0) {
                        let payload_type = state.mmu.arena[phys_addr];

                        if payload_type == 0xCC {
                            // 0xCC simulando un 'opcode' de escalamiento
                            state.user_privileged = true;
                            let _ = stream.write_all(b"OK: PRIVILEGE ESCALATION SUCCESSFUL");
                        } else {
                            println!(" [KERNEL] Unrecognized instruction {} at 0x0", payload_type);
                            let _ = stream
                                .write_all(b"ERROR: Kernel Panic - Invalid Instruction at 0x0");
                        }
                    } else {
                        let _ = stream
                            .write_all(b"ERROR: Kernel Panic - Segmentation Fault (Simulated)");
                    }
                } else {
                    let _ = stream.write_all(b"ERROR: Unavailable syscall.");
                }
            }

            "ECHO_ROOT" => {
                if state.user_privileged {
                    println!(" [KERNEL_AUTH_LOG]: {}", cmd[1..].join(" "));
                    let _ = stream.write_all(b"OK: Message logged as root\n");
                } else {
                    println!(" [SECURITY_ALERT]: Unauthorized.");
                    let _ = stream.write_all(b"ERROR: Unauthorized\n");
                }
            }
            _ => {
                let _ = stream.write_all(b"ERROR: Unknown command\n");
            }
        }
    }
}
