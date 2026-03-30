use crate::transport::{
    ClientPacket, EncryptedBlob, RequestAuth, ServerPacket, auth_signing_payload, decode_packet,
    encode_packet, read_framed, write_framed,
};
use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngExt;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

pub fn issue_rid(addr: &str, signing_key: &SigningKey) -> Result<ServerPacket> {
    let auth = make_auth(signing_key, "issue_rid", b"");
    send_client_packet(addr, ClientPacket::IssueRid { auth })
}

pub fn rotate_rid(addr: &str, signing_key: &SigningKey, rid: &str) -> Result<ServerPacket> {
    let auth = make_auth(signing_key, "rotate_rid", rid.as_bytes());
    send_client_packet(
        addr,
        ClientPacket::RotateRid {
            rid: rid.to_string(),
            auth,
        },
    )
}

pub fn fetch_queued(addr: &str, signing_key: &SigningKey, rid: &str) -> Result<ServerPacket> {
    let auth = make_auth(signing_key, "fetch_queued", rid.as_bytes());
    send_client_packet(
        addr,
        ClientPacket::FetchQueued {
            rid: rid.to_string(),
            auth,
        },
    )
}

pub fn put_blob(addr: &str, blob: EncryptedBlob) -> Result<ServerPacket> {
    send_client_packet(addr, ClientPacket::PutBlob { blob })
}

pub fn send_client_packet(addr: &str, packet: ClientPacket) -> Result<ServerPacket> {
    let mut stream = TcpStream::connect(addr).with_context(|| format!("connect to {}", addr))?;
    let bytes = encode_packet(&packet)?;
    write_framed(&mut stream, &bytes)?;
    let frame = read_framed(&mut stream, MAX_FRAME_BYTES)?;
    let response: ServerPacket = decode_packet(&frame)?;
    Ok(response)
}

fn make_auth(signing_key: &SigningKey, action: &str, body: &[u8]) -> RequestAuth {
    let mut nonce = [0_u8; 16];
    rand::rng().fill(&mut nonce);

    let mut auth = RequestAuth {
        credential_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        nonce: nonce.to_vec(),
        signed_at_unix_ms: unix_ms_now(),
        signature: Vec::new(),
    };

    let payload = auth_signing_payload(action, body, &auth);
    auth.signature = signing_key.sign(&payload).to_bytes().to_vec();
    auth
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
