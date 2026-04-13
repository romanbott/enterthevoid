use clap::Parser;
use enterthevoid::ipc::{IpcRequest, IpcResponse, receive_message, send_message};
use enterthevoid::mmu::Mmu;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

/// Command line arguments for the Kernel simulator.
#[derive(Parser)]
struct Args {
    /// Enables vulnerable syscalls.
    #[arg(long)]
    vulnerable: bool,
    /// Allows logical mapping to page zero.
    #[arg(long)]
    allow_page_zero: bool,
}

/// Holds the execution context and privileges for a connected session.
struct KernelState {
    mmu: Mmu,
    user_privileged: bool,
    user_name: String,
}

fn main() {
    let args = Args::parse();
    let socket_path = "/tmp/rust_os_sim.sock";

    // Clean up previous socket if it exists
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path).expect("Failed to bind to socket");
    println!(" [KERNEL] Waiting for user login...");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // Spawn a new thread for each client to handle multiple simultaneous connections
                let args_clone = Args {
                    vulnerable: args.vulnerable,
                    allow_page_zero: args.allow_page_zero,
                };
                thread::spawn(move || {
                    handle_client(&mut stream, &args_clone);
                });
            }
            Err(e) => eprintln!(" [KERNEL] Connection Error: {}", e),
        }
    }
}

/// Main loop for handling IPC requests from a connected client.
fn handle_client(stream: &mut UnixStream, args: &Args) {
    let mut buffer = [0; 2048];

    // Initial handshake / login
    let mut state = match receive_message::<IpcRequest>(stream, &mut buffer) {
        Ok(Some(IpcRequest::Login { username })) => KernelState {
            mmu: Mmu::new(),
            user_privileged: false,
            user_name: username,
        },
        _ => {
            eprintln!(" [KERNEL] Invalid login sequence. Closing connection.");
            return;
        }
    };

    println!(
        " [KERNEL] User {} (root: {}) connected",
        state.user_name, state.user_privileged
    );

    loop {
        match receive_message::<IpcRequest>(stream, &mut buffer) {
            Ok(Some(request)) => process_request(stream, &mut state, args, request),
            Ok(None) => {
                println!(" [KERNEL] User {} disconnected.", state.user_name);
                break;
            }
            Err(e) => {
                eprintln!(" [KERNEL] IPC Read Error: {}", e);
                break;
            }
        }
    }
}

/// Routes and executes an incoming IPC request.
fn process_request(
    stream: &mut UnixStream,
    state: &mut KernelState,
    args: &Args,
    request: IpcRequest,
) {
    let response = match request {
        IpcRequest::Login { .. } => IpcResponse::Error("Already logged in".to_string()),

        IpcRequest::WriteLogical { addr, value } => match state.mmu.write(addr, value) {
            Ok(_) => IpcResponse::Ok("Write Successful".to_string()),
            Err(e) => IpcResponse::Error(format!("Page Fault on Write: {}", e)),
        },

        IpcRequest::ReadLogical { addr } => match state.mmu.read(addr) {
            Ok(val) => IpcResponse::Value(val),
            Err(e) => IpcResponse::Error(format!("Page Fault on Read: {}", e)),
        },

        IpcRequest::MmapLogical { addr } => {
            if state.mmu.get_page_num(addr) == 0 && !args.allow_page_zero {
                IpcResponse::Error("Security Policy: Page Zero mapping forbidden".to_string())
            } else {
                match state.mmu.map_page(addr) {
                    Ok(_) => {
                        println!(" [KERNEL] MMU: Address {} mapped.", addr);
                        IpcResponse::Ok("Mapped successfully".to_string())
                    }
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
        }

        IpcRequest::MakeRoot => {
            if state.user_privileged {
                IpcResponse::Ok("You are already root.".to_string())
            } else {
                println!(
                    " [SECURITY_ALERT] Unauthorized privilege escalation attempt by user: {}",
                    state.user_name
                );
                IpcResponse::Error("Unauthorized. (PSW.mode == 0)".to_string())
            }
        }

        IpcRequest::SysVuln => {
            if args.vulnerable {
                match state.mmu.read(0) {
                    Ok(0xCC) => {
                        // 0xCC simulating a privilege escalation shellcode execution
                        state.user_privileged = true;
                        IpcResponse::Ok("PRIVILEGE ESCALATION SUCCESSFUL".to_string())
                    }
                    Ok(payload) => {
                        println!(
                            " [KERNEL] Unrecognized instruction 0x{:02X} at 0x0",
                            payload
                        );
                        IpcResponse::Error("Kernel Panic - Invalid Instruction at 0x0".to_string())
                    }
                    Err(_) => IpcResponse::Error(
                        "Kernel Panic - Segmentation Fault (Simulated)".to_string(),
                    ),
                }
            } else {
                IpcResponse::Error("Unavailable syscall (Not vulnerable).".to_string())
            }
        }

        IpcRequest::EchoRoot { message } => {
            if state.user_privileged {
                println!(" [KERNEL_AUTH_LOG]: {}", message);
                IpcResponse::Ok("Message logged as root".to_string())
            } else {
                println!(
                    " [SECURITY_ALERT] Unauthorized attempt to write to kernel buffer by user: {}",
                    state.user_name
                );
                IpcResponse::Error("Unauthorized".to_string())
            }
        }
    };

    let _ = send_message(stream, &response);
}
