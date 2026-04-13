use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// Requests sent from the user-space process to the simulated kernel.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    Login { username: String },
    WriteLogical { addr: usize, value: u8 },
    ReadLogical { addr: usize },
    MmapLogical { addr: usize },
    MakeRoot,
    SysVuln,
    EchoRoot { message: String },
}

/// Responses sent from the simulated kernel back to the user-space process.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok(String),
    Error(String),
    Value(u8),
}

/// Helper function to transmit an IPC message over a Unix socket.
pub fn send_message<T: Serialize>(stream: &mut UnixStream, msg: &T) -> std::io::Result<()> {
    let serialized = serde_json::to_string(msg)?;
    let mut payload = serialized.into_bytes();
    payload.push(b'\n');
    stream.write_all(&payload)?;
    stream.flush()
}

/// Helper function to receive an IPC message from a Unix socket.
pub fn receive_message<'a, T: Deserialize<'a>>(
    stream: &mut UnixStream,
    buffer: &'a mut [u8],
) -> std::io::Result<Option<IpcResponse>> {
    let bytes_read = stream.read(buffer)?;
    if bytes_read == 0 {
        return Ok(None);
    }

    // Ignore trailing newlines for JSON parsing
    let payload = &buffer[..bytes_read];
    let json_str = std::str::from_utf8(payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .trim();

    if json_str.is_empty() {
        return Ok(None);
    }

    let msg = serde_json::from_str(json_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}
