//! Post-verifySdk login chain: CS_Login, PhonestGate.bind, and helpers to
//! carry the session onto the WORLD gate (connectServer + stream capture).
//!
//! Everything here is built from the capture-decoded messages documented in
//! PLAN.md ("THE 573B MYSTERY SOLVED"): the verifySdk response issues the
//! login-auth blob (pre-encoded msgpack {Username, Expired, Sign}) that
//! CS_Login forwards positionally; PhonestGate.bind carries the game uid;
//! the world gate takes connectServer{auth} and answers with the save
//! stream.

use crate::GateError;

/// Minimal msgpack reader - just enough to walk MsResponse params and find
/// the login-auth map the native client forwards into CS_Login.
pub mod mp {
    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Nil,
        Bool(bool),
        Uint(u64),
        Int(i64),
        Str(Vec<u8>),
        Bin(Vec<u8>),
        Array(Vec<Value>),
        Map(Vec<(Value, Value)>),
    }

    impl Value {
        pub fn as_str(&self) -> Option<&[u8]> {
            match self {
                Value::Str(b) | Value::Bin(b) => Some(b),
                _ => None,
            }
        }
        pub fn as_u64(&self) -> Option<u64> {
            match self {
                Value::Uint(v) => Some(*v),
                Value::Int(v) => u64::try_from(*v).ok(),
                _ => None,
            }
        }
        pub fn get(&self, key: &str) -> Option<&Value> {
            if let Value::Map(pairs) = self {
                for (k, v) in pairs {
                    if k.as_str().map(|b| b == key.as_bytes()).unwrap_or(false) {
                        return Some(v);
                    }
                }
            }
            None
        }
    }

    /// Parse one msgpack value; returns the value and bytes consumed.
    pub fn parse(data: &[u8]) -> Option<(Value, usize)> {
        let (&tag, rest) = data.split_first()?;
        // total bytes consumed when `extra` bytes follow the tag
        let used = |extra: usize| data.len() - rest.len() + extra;
        Some(match tag {
            0xc0 => (Value::Nil, used(0)),
            0xc2 => (Value::Bool(false), used(0)),
            0xc3 => (Value::Bool(true), used(0)),
            0xc4..=0xc6 => {
                let (n, off) = read_len(rest, tag - 0xc4)?;
                let n = n as usize;
                if rest.len() < off + n {
                    return None;
                }
                (Value::Bin(rest[off..off + n].to_vec()), used(off + n))
            }
            0xcc => read_uint(rest, 1)?,
            0xcd => read_uint(rest, 2)?,
            0xce => read_uint(rest, 4)?,
            0xcf => read_uint(rest, 8)?,
            0xd0 => read_int(rest, 1)?,
            0xd1 => read_int(rest, 2)?,
            0xd2 => read_int(rest, 4)?,
            0xd3 => read_int(rest, 8)?,
            0xa0..=0xbf => read_str(data, rest, (tag & 0x1f) as usize)?,
            0xd9 => {
                let (&n, r) = rest.split_first()?;
                read_str(data, r, n as usize)?
            }
            0xda => {
                if rest.len() < 2 {
                    return None;
                }
                let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                read_str(data, &rest[2..], n)?
            }
            0xdb => {
                if rest.len() < 4 {
                    return None;
                }
                let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                read_str(data, &rest[4..], n)?
            }
            0xdc => {
                let (n, off) = read_len(rest, 2)?;
                read_array(data, rest, off, n as usize)?
            }
            0xdd => {
                let (n, off) = read_len(rest, 4)?;
                read_array(data, rest, off, n as usize)?
            }
            0xde => {
                let (n, off) = read_len(rest, 2)?;
                read_map(data, rest, off, n as usize)?
            }
            0xdf => {
                let (n, off) = read_len(rest, 4)?;
                read_map(data, rest, off, n as usize)?
            }
            t if t & 0xe0 == 0xa0 => read_str(data, rest, (t & 0x1f) as usize)?,
            t if t & 0xe0 == 0xe0 => (Value::Int(tag as i8 as i64), used(0)),
            t if t & 0xf0 == 0x90 => {
                let items = (t & 0x0f) as usize;
                read_array(data, rest, 0, items)?
            }
            t if t & 0x80 == 0x80 => {
                let items = (t & 0x0f) as usize;
                read_map(data, rest, 0, items)?
            }
            t if t & 0x80 == 0 => (Value::Uint(t as u64), used(0)),
            _ => return None, // float/ext: not needed for gate traffic
        })
    }

    fn read_len(rest: &[u8], width: u8) -> Option<(u64, usize)> {
        let w = width as usize + 1;
        if rest.len() < w {
            return None;
        }
        let mut v = 0u64;
        for b in &rest[..w] {
            v = (v << 8) | *b as u64;
        }
        Some((v, w))
    }

    fn read_uint(rest: &[u8], width: usize) -> Option<((Value, usize))> {
        if rest.len() < width {
            return None;
        }
        let mut v = 0u64;
        for b in &rest[..width] {
            v = (v << 8) | *b as u64;
        }
        Some(((Value::Uint(v)), width + 1))
    }

    fn read_int(rest: &[u8], width: usize) -> Option<((Value, usize))> {
        let (v, n) = read_uint(rest, width)?;
        let raw = match v {
            Value::Uint(v) => v as i64,
            _ => return None,
        };
        let shift = 64 - width as u32 * 8;
        Some(((Value::Int((raw << shift) >> shift)), n))
    }

    fn read_str(data: &[u8], rest: &[u8], n: usize) -> Option<((Value, usize))> {
        if rest.len() < n {
            return None;
        }
        let total = data.len() - rest.len() + n;
        Some(((Value::Str(data[total - n..total].to_vec())), total))
    }

    fn read_array(data: &[u8], rest: &[u8], off: usize, items: usize) -> Option<((Value, usize))> {
        let mut cur = &rest[off..];
        let mut base = data.len() - rest.len() + off;
        let mut out = Vec::with_capacity(items);
        for _ in 0..items {
            let (v, used) = parse(cur)?;
            out.push(v);
            base += used;
            cur = &cur[used..];
        }
        Some(((Value::Array(out)), base))
    }

    fn read_map(data: &[u8], rest: &[u8], off: usize, items: usize) -> Option<((Value, usize))> {
        let mut cur = &rest[off..];
        let mut base = data.len() - rest.len() + off;
        let mut out = Vec::with_capacity(items);
        for _ in 0..items {
            let (k, used) = parse(cur)?;
            base += used;
            cur = &cur[used..];
            let (v, used) = parse(cur)?;
            base += used;
            cur = &cur[used..];
            out.push((k, v));
        }
        Some(((Value::Map(out)), base))
    }

    // ---- writers ----

    pub fn write_str(out: &mut Vec<u8>, s: &[u8]) {
        let n = s.len();
        if n <= 31 {
            out.push(0xa0 | n as u8);
        } else if n <= 255 {
            out.push(0xd9);
            out.push(n as u8);
        } else if n <= 65535 {
            out.push(0xda);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(0xdb);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        out.extend_from_slice(s);
    }

    pub fn write_uint(out: &mut Vec<u8>, v: u64) {
        if v < 128 {
            out.push(v as u8);
        } else if v <= u8::MAX as u64 {
            out.push(0xcc);
            out.push(v as u8);
        } else if v <= u16::MAX as u64 {
            out.push(0xcd);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= u32::MAX as u64 {
            out.push(0xce);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            out.push(0xcf);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }

    pub fn write_bin(out: &mut Vec<u8>, b: &[u8]) {
        out.push(0xc4);
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }

    pub fn write_map_header(out: &mut Vec<u8>, items: usize) {
        if items <= 15 {
            out.push(0x80 | items as u8);
        } else {
            out.push(0xde);
            out.extend_from_slice(&(items as u16).to_be_bytes());
        }
    }

    pub fn write_array_header(out: &mut Vec<u8>, items: usize) {
        if items <= 15 {
            out.push(0x90 | items as u8);
        } else {
            out.push(0xdc);
            out.extend_from_slice(&(items as u16).to_be_bytes());
        }
    }
}

/// The login-auth payload the verifySdk response issues and CS_Login
/// forwards: msgpack {Username, Expired, Sign}.
#[derive(Debug, Clone, PartialEq)]
pub struct LoginAuth {
    pub username: String,
    pub expired: u64,
    pub sign: String,
    /// the raw forwarded bytes (a msgpack string body containing a msgpack
    /// map) - CS_Login sends this verbatim as its second positional arg.
    pub raw: Vec<u8>,
}

/// Walk the verifySdk response params and pull out the login-auth blob.
/// The native client forwards a msgpack string whose payload is itself a
/// msgpack map; accept both the nested and the direct form, scanning
/// aggressively because the exact outer wrapper has only been seen in
/// captures, not in a schema.
pub fn extract_login_auth(params: &[u8]) -> Option<LoginAuth> {
    let mut queue = vec![params.to_vec()];
    let mut tried = Vec::new();
    while let Some(data) = queue.pop() {
        if tried.iter().any(|t: &Vec<u8>| t == &data) {
            continue;
        }
        tried.push(data.clone());
        if let Some((v, _)) = mp::parse(&data) {
            // direct hit: top-level map with Sign
            if let Some(a) = auth_from_map(&v) {
                return Some(a);
            }
            // walk structure: every string that itself parses as msgpack
            // gets queued; so does every container element.
            walk(&v, &mut queue);
        }
        // brute scan: a msgpack str header immediately followed by a map
        for i in 0..data.len().saturating_sub(4) {
            let candidate = &data[i..];
            let (v, used) = match mp::parse(candidate) {
                Some(pair) => pair,
                None => continue,
            };
            if let Some(a) = auth_from_map(&v) {
                let raw = candidate[..used].to_vec();
                return Some(LoginAuth { raw, ..a });
            }
        }
    }
    None
}

fn walk(v: &mp::Value, queue: &mut Vec<Vec<u8>>) {
    match v {
        mp::Value::Str(b) | mp::Value::Bin(b) => queue.push(b.clone()),
        mp::Value::Array(items) => items.iter().for_each(|i| walk(i, queue)),
        mp::Value::Map(pairs) => {
            for (k, val) in pairs {
                walk(k, queue);
                walk(val, queue);
            }
        }
        _ => {}
    }
}

fn auth_from_map(v: &mp::Value) -> Option<LoginAuth> {
    let sign = v.get("Sign")?.as_str()?;
    if sign.len() != 64 {
        return None;
    }
    let username = String::from_utf8(v.get("Username")?.as_str()?.to_vec()).ok()?;
    let expired = v.get("Expired")?.as_u64()?;
    let mut raw = Vec::new();
    mp::write_map_header(&mut raw, 3);
    mp::write_str(&mut raw, b"Username");
    mp::write_str(&mut raw, username.as_bytes());
    mp::write_str(&mut raw, b"Expired");
    mp::write_uint(&mut raw, expired);
    mp::write_str(&mut raw, b"Sign");
    mp::write_str(&mut raw, sign);
    Some(LoginAuth {
        username,
        expired,
        sign: String::from_utf8(sign.to_vec()).ok()?,
        raw,
    })
}

/// Runtime knobs for CS_Login's positional args. Defaults come from the
/// capture-decoded 2026-09-25 login; override via the credentials file or
/// CLI when the server ships new values.
#[derive(Debug, Clone)]
pub struct CsLoginConfig {
    pub client_version: String,
    pub client_config_version: String,
    pub server_id: u64,
    pub scene_id: u64,
    pub region_no: u64,
    /// 12-byte ObjectId-style session id (reused from the banked capture).
    pub session_id: [u8; 12],
    /// 12-byte ObjectId-style gate id.
    pub gate_id: [u8; 12],
    pub language: String,
    /// The 1875B sdkInfo JSON the C# SDKManager builds. Supply the banked
    /// capture blob for byte-parity; a synthesized minimum also works when
    /// the server is lenient.
    pub sdk_info_json: String,
}

/// CS_Login params: fixarray5
/// [account_id, login-auth blob, gate map, sdkInfo json, enrich map].
pub fn cs_login_params(
    account_id: &str,
    auth_blob: &[u8],
    uid: u64,
    cfg: &CsLoginConfig,
) -> Vec<u8> {
    let mut p = Vec::new();
    mp::write_array_header(&mut p, 5);
    // [0] account id
    mp::write_str(&mut p, account_id.as_bytes());
    // [1] the verifySdk-issued auth blob, forwarded verbatim
    p.extend_from_slice(auth_blob);
    // [2] gate map
    mp::write_map_header(&mut p, 7);
    mp::write_str(&mut p, b"regionNo");
    mp::write_uint(&mut p, cfg.region_no);
    mp::write_str(&mut p, b"sessionId");
    mp::write_bin(&mut p, &cfg.session_id);
    mp::write_str(&mut p, b"clientVersion");
    mp::write_str(&mut p, cfg.client_version.as_bytes());
    mp::write_str(&mut p, b"DEFAULT_SCENE_ID");
    mp::write_uint(&mut p, cfg.scene_id);
    mp::write_str(&mut p, b"serverId");
    mp::write_uint(&mut p, cfg.server_id);
    mp::write_str(&mut p, b"clientConfigVersion");
    mp::write_str(&mut p, cfg.client_config_version.as_bytes());
    mp::write_str(&mut p, b"gateId");
    mp::write_bin(&mut p, &cfg.gate_id);
    // [3] sdkInfo json
    mp::write_str(&mut p, cfg.sdk_info_json.as_bytes());
    // [4] enrich map
    mp::write_map_header(&mut p, 8);
    mp::write_str(&mut p, b"platformUserId");
    mp::write_uint(&mut p, uid);
    mp::write_str(&mut p, b"playerTags");
    mp::write_array_header(&mut p, 0);
    mp::write_str(&mut p, b"gamePlatform");
    mp::write_str(&mut p, b"PC");
    mp::write_str(&mut p, b"platformFamily");
    mp::write_str(&mut p, b"other");
    mp::write_str(&mut p, b"avatarConfig");
    mp::write_str(&mut p, b"");
    mp::write_str(&mut p, b"language");
    mp::write_str(&mut p, cfg.language.as_bytes());
    mp::write_str(&mut p, b"playerName");
    mp::write_str(&mut p, b"");
    mp::write_str(&mut p, b"avatarPresetKey");
    mp::write_uint(&mut p, 0);
    p
}

/// PhonestGate.bind params: fixarray[uid].
pub fn bind_params(uid: u64) -> Vec<u8> {
    let mut p = Vec::new();
    mp::write_array_header(&mut p, 1);
    mp::write_uint(&mut p, uid);
    p
}

impl crate::session::LiveSession {
    /// RoleService.CS_Login - the second message of the real login.
    pub fn cs_login(
        &mut self,
        account_id: &str,
        auth_blob: &[u8],
        uid: u64,
        cfg: &CsLoginConfig,
    ) -> Result<Vec<u8>, GateError> {
        self.call_ms(
            "RoleService",
            "CS_Login",
            &cs_login_params(account_id, auth_blob, uid, cfg),
            std::time::Duration::from_secs(12),
        )
    }

    /// PhonestGate.bind - announces the game uid on the login gate.
    pub fn phonest_bind(&mut self, uid: u64) -> Result<Vec<u8>, GateError> {
        self.call_ms(
            "PhonestGate",
            "bind",
            &bind_params(uid),
            std::time::Duration::from_secs(12),
        )
    }
}

/// Build the world-gate connectServer with the verifySdk token as auth.
pub fn world_connect_server(
    auth: &[u8],
    version: &str,
    device_id: &[u8],
) -> crate::handshake::ConnectServerReq {
    crate::handshake::ConnectServerReq {
        req_type: crate::handshake::ConnectReqType::NewConnection,
        device_id: Some(device_id.to_vec()),
        auth: Some(auth.to_vec()),
        entity_info: None,
        version: Some(version.to_string()),
        last_client_rpc_seq_id: None,
    }
}

/// Dump helper: length-prefixed record file the census/LuaLazyDecoder tools
/// read (u16 method + u32 len + body per record).
pub fn write_stream_dump(path: &std::path::Path, frames: &[(u16, Vec<u8>)]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    for (method, body) in frames {
        f.write_all(&method.to_le_bytes())?;
        f.write_all(&(body.len() as u32).to_le_bytes())?;
        f.write_all(body)?;
    }
    f.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_auth_roundtrip() {
        // what a verifySdk response carries: nested msgpack-str(msgpack map)
        let mut inner = Vec::new();
        mp::write_map_header(&mut inner, 3);
        mp::write_str(&mut inner, b"Username");
        mp::write_str(&mut inner, b"fp_account_global:2044122406");
        mp::write_str(&mut inner, b"Expired");
        mp::write_uint(&mut inner, 1790390387);
        mp::write_str(&mut inner, b"Sign");
        mp::write_str(&mut inner, &vec![b'a'; 64]);
        let mut outer = vec![0x90]; // some response wrapper prefix
        mp::write_str(&mut outer, &inner);
        let auth = extract_login_auth(&outer).expect("auth blob must be found");
        assert_eq!(auth.username, "fp_account_global:2044122406");
        assert_eq!(auth.expired, 1790390387);
        assert_eq!(auth.sign.len(), 64);
        // forwarded blob == inner bytes
        assert_eq!(auth.raw, inner);
    }

    #[test]
    fn cs_login_params_shape() {
        let cfg = CsLoginConfig {
            client_version: "2026092202".into(),
            client_config_version: "278da592".into(),
            server_id: 100,
            scene_id: 3002,
            region_no: 0,
            session_id: [1; 12],
            gate_id: [2; 12],
            language: "en".into(),
            sdk_info_json: "{}".into(),
        };
        let mut raw = Vec::new();
        mp::write_map_header(&mut raw, 3);
        mp::write_str(&mut raw, b"Username");
        mp::write_str(&mut raw, b"u");
        mp::write_str(&mut raw, b"Expired");
        mp::write_uint(&mut raw, 1);
        mp::write_str(&mut raw, b"Sign");
        mp::write_str(&mut raw, &vec![b'a'; 64]);
        let auth = LoginAuth {
            username: "u".into(),
            expired: 1,
            sign: "s".into(),
            raw,
        };
        let p = cs_login_params("fp_account_global:2044122406", &auth.raw, 302001142689, &cfg);
        // fixarray5
        assert_eq!(p[0], 0x95);
        // full params must reparse as a 5-element array
        let (v, used) = mp::parse(&p).expect("params parse");
        assert_eq!(used, p.len());
        match v {
            mp::Value::Array(items) => assert_eq!(items.len(), 5),
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn bind_params_shape() {
        let p = bind_params(302001142689);
        let mut want = vec![0x91, 0xcf];
        want.extend_from_slice(&302001142689u64.to_be_bytes());
        assert_eq!(p, want);
        // and it must parse back
        if let Some((mp::Value::Array(items), 10)) = mp::parse(&p) {
            assert_eq!(items.len(), 1);
        } else {
            panic!("bind params must reparse as a 1-element array");
        }
    }

    #[test]
    fn world_connect_request_fields() {
        let req = world_connect_server(b"auth-token", "2026092202", b"device");
        let m = req.encode_pb();
        let parsed = crate::pb::decode(&m).unwrap();
        assert_eq!(parsed.varint(1), Some(0));
        assert_eq!(parsed.bytes(4), Some(b"auth-token".as_slice()));
        assert_eq!(parsed.string(6).as_deref(), Some("2026092202"));
    }
}

