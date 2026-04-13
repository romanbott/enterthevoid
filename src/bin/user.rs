use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

fn enviar_comando(stream: &mut UnixStream, cmd: &str) {
    let mut mensaje = cmd.to_string();
    mensaje.push('\n');
    stream
        .write_all(mensaje.as_bytes())
        .expect("Error al escribir en socket");
}

fn main() {
    let socket_path = "/tmp/rust_os_sim.sock";
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => {
            println!(" [!] Error: No se pudo conectar con el kernel (kernel_sim).");
            println!("     Asegúrate de que el kernel se esté ejecutando primero.");
            return;
        }
    };

    println!(" --- ENTER THE VOID: USER SHELL ---");

    print!("login: ");
    io::stdout().flush().unwrap();
    let mut user_name = String::new();
    io::stdin().read_line(&mut user_name).unwrap();

    enviar_comando(&mut stream, user_name.trim());

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).unwrap() == 0 {
            break;
        } // EOF (Ctrl+D)

        let tokens: Vec<&str> = input.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let command = tokens[0];

        match command {
            // --- COMANDOS DE MEMORIA ---
            "mmap" => {
                if let Some(addr) = tokens.get(1) {
                    enviar_comando(&mut stream, &format!("MMAP_LOGICAL {}", addr));
                    recibir_respuesta(&mut stream);
                } else {
                    println!(" Uso: mmap <direccion_logica>");
                }
            }

            "write" => {
                if let (Some(addr), Some(val)) = (tokens.get(1), tokens.get(2)) {
                    enviar_comando(&mut stream, &format!("WRITE_LOGICAL {} {}", addr, val));
                    recibir_respuesta(&mut stream);
                } else {
                    println!(" Uso: write <addr> <val>");
                }
            }

            "read" => {
                if let Some(addr) = tokens.get(1) {
                    enviar_comando(&mut stream, &format!("READ_LOGICAL {}", addr));
                    recibir_respuesta(&mut stream);
                } else {
                    println!(" Uso: read <addr>");
                }
            }

            // --- COMANDOS DE PRIVILEGIOS ---
            "su" => {
                enviar_comando(&mut stream, "MAKE_ROOT");
                recibir_respuesta(&mut stream);
            }

            "echo_root" => {
                if tokens.len() > 1 {
                    let mensaje = tokens[1..].join(" ");
                    enviar_comando(&mut stream, &format!("ECHO_ROOT {}", mensaje));
                    recibir_respuesta(&mut stream);
                } else {
                    println!(" Uso: echo_root <mensaje>");
                }
            }

            // --- EXPLOIT & VULNERABILIDAD ---
            "sys_vuln" => {
                enviar_comando(&mut stream, "SYS_VULN");
                recibir_respuesta(&mut stream);
            }

            "exploit" | "exploit.sh" | "pwn.sh" => {
                realizar_exploit(&mut stream);
            }

            "exit" | "quit" => break,

            _ => println!(
                " Unrecognized command. Available: mmap, write, read, su, echo_root, sys_vuln, exploit, exit"
            ),
        }
    }
}

fn recibir_respuesta(stream: &mut UnixStream) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let respuesta = String::from_utf8_lossy(&buffer[..n]);
            println!(" [KERNEL] {}", respuesta);
        }
        _ => println!(" [!] Sin respuesta del kernel."),
    }
}

fn realizar_exploit(stream: &mut UnixStream) {
    println!(" [!] Iniciando secuencia de exploit...");

    // 1. Mapear página cero
    println!(" [1/3] Mapeando página lógica 0x0...");
    enviar_comando(stream, "MMAP_LOGICAL 0");
    recibir_respuesta(stream);

    // 2. Inyectar opcode de escalamiento (0xCC = 204)
    println!(" [2/3] Inyectando payload (0xCC) en memoria física vía MMU...");
    enviar_comando(stream, "WRITE_LOGICAL 0 0xCC");
    recibir_respuesta(stream);

    // 3. Disparar desreferencia en el Kernel
    println!(" [3/3] Ejecutando syscall vulnerable (SYS_VULN)...");
    enviar_comando(stream, "SYS_VULN");
    recibir_respuesta(stream);
}
