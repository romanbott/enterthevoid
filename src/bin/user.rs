use enterthevoid::ipc::{IpcRequest, IpcResponse, receive_message, send_message};
use std::io::{self, Write};
use std::os::unix::net::UnixStream;

/// Parses a string into a number, supporting hex (0x...) or decimal format.
fn parse_number(input: &str) -> Option<usize> {
    if let Some(hex_val) = input.strip_prefix("0x") {
        usize::from_str_radix(hex_val, 16).ok()
    } else {
        input.parse().ok()
    }
}

/// Parses a string into a byte, supporting hex (0x...) or decimal format.
fn parse_byte(input: &str) -> Option<u8> {
    if let Some(hex_val) = input.strip_prefix("0x") {
        u8::from_str_radix(hex_val, 16).ok()
    } else {
        input.parse().ok()
    }
}

fn main() {
    let socket_path = "/tmp/rust_os_sim.sock";
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => {
            println!(" [!] Error: Could not connect to the kernel (kernel_sim).");
            println!("     Make sure the kernel is running first.");
            return;
        }
    };

    println!(" --- ENTER THE VOID: USER SHELL ---");

    print!("login: ");
    io::stdout().flush().unwrap();
    let mut user_name = String::new();
    io::stdin().read_line(&mut user_name).unwrap();

    // Send login handshake
    let login_req = IpcRequest::Login {
        username: user_name.trim().to_string(),
    };
    if send_message(&mut stream, &login_req).is_err() {
        println!(" [!] Error authenticating with the kernel.");
        return;
    }

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).unwrap() == 0 {
            break; // EOF (Ctrl+D)
        }

        let tokens: Vec<&str> = input.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let request = match tokens[0] {
            "mmap" => {
                if let Some(addr_str) = tokens.get(1) {
                    if let Some(addr) = parse_number(addr_str) {
                        Some(IpcRequest::MmapLogical { addr })
                    } else {
                        println!(" [!] Invalid address.");
                        None
                    }
                } else {
                    println!(" Usage: mmap <logical_address>");
                    None
                }
            }

            "write" => {
                if let (Some(addr_str), Some(val_str)) = (tokens.get(1), tokens.get(2)) {
                    if let (Some(addr), Some(value)) = (parse_number(addr_str), parse_byte(val_str))
                    {
                        Some(IpcRequest::WriteLogical { addr, value })
                    } else {
                        println!(" [!] Invalid arguments.");
                        None
                    }
                } else {
                    println!(" Usage: write <addr> <val> (supports 0x...)");
                    None
                }
            }

            "read" => {
                if let Some(addr_str) = tokens.get(1) {
                    if let Some(addr) = parse_number(addr_str) {
                        Some(IpcRequest::ReadLogical { addr })
                    } else {
                        println!(" [!] Invalid address.");
                        None
                    }
                } else {
                    println!(" Usage: read <addr>");
                    None
                }
            }

            "su" => Some(IpcRequest::MakeRoot),

            "echo_root" => {
                if tokens.len() > 1 {
                    Some(IpcRequest::EchoRoot {
                        message: tokens[1..].join(" "),
                    })
                } else {
                    println!(" Usage: echo_root <message>");
                    None
                }
            }

            "sys_vuln" => Some(IpcRequest::SysVuln),

            "exploit" | "exploit.sh" | "pwn.sh" => {
                execute_exploit(&mut stream);
                None // Exploit handled internally
            }

            "exit" | "quit" => break,

            _ => {
                println!(
                    " Unrecognized command. Available: mmap, write, read, su, echo_root, sys_vuln, exploit, exit"
                );
                None
            }
        };

        if let Some(req) = request {
            if send_message(&mut stream, &req).is_ok() {
                receive_response(&mut stream);
            } else {
                println!(" [!] Communication error with the kernel.");
                break;
            }
        }
    }
}

/// Waits for and prints the response from the kernel.
fn receive_response(stream: &mut UnixStream) {
    let mut buffer = [0; 2048];
    match receive_message::<IpcResponse>(stream, &mut buffer) {
        Ok(Some(IpcResponse::Ok(msg))) => println!(" [KERNEL] OK: {}", msg),
        Ok(Some(IpcResponse::Error(err))) => println!(" [KERNEL] ERROR: {}", err),
        Ok(Some(IpcResponse::Value(val))) => println!(" [KERNEL] VALUE: 0x{:02X}", val),
        Ok(None) => println!(" [!] Connection closed by the kernel."),
        Err(_) => println!(" [!] Error reading response from kernel."),
    }
}

/// Executes the automated exploit sequence simulating a Null Pointer Dereference
/// combined with arbitrary execution.
fn execute_exploit(stream: &mut UnixStream) {
    println!(" [!] Initiating exploit sequence...");

    // 1. Map logical page zero
    println!(" [1/3] Mapping logical page 0x0...");
    let _ = send_message(stream, &IpcRequest::MmapLogical { addr: 0 });
    receive_response(stream);

    // 2. Inject shellcode payload (0xCC)
    println!(" [2/3] Injecting payload (0xCC) into memory...");
    let _ = send_message(
        stream,
        &IpcRequest::WriteLogical {
            addr: 0,
            value: 0xCC,
        },
    );
    receive_response(stream);

    // 3. Trigger kernel vulnerability
    println!(" [3/3] Executing vulnerable syscall (SYS_VULN)...");
    let _ = send_message(stream, &IpcRequest::SysVuln);
    receive_response(stream);
}
