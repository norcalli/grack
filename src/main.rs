use anyhow::{ensure, Result};
use itertools::structs::MultiPeek;
use itertools::Itertools;
use json::JsonValue;
use std::io::{BufRead, Read, Write};
use vmap::io::{BufReader, BufWriter};

#[derive(Debug)]
pub struct Settings {
    pub hide_array_index: bool,
    pub hide_map_index: bool,
    pub inline_map_key: bool,
    pub inline_array: bool,
    pub inline_map: bool,
}

macro_rules! parse {
    ($($f:ident[$($alias:ident),*] $method:ident: $default:expr,)+) => {
        pub fn extract_info() -> &'static [(&'static [&'static str], &'static str, &'static str)] {
            &[
                $((&[stringify!($f), $(stringify!($alias)),*], stringify!($method), stringify!($default))),+
            ]
        }

        pub fn extract(value: &JsonValue) -> Self {
            Self {
                $(
                    $f: value[stringify!($f)].$method()
                        $(.or_else(|| value[stringify!($alias)].$method()))*
                        .unwrap_or_else(|| $default),
                    )+
            }
        }

        pub fn to_value(&self) -> JsonValue {
            json::object! { $($f: self.$f),+ }
        }
    };
}

impl Settings {
    parse! {
        hide_array_index[ha] as_bool: false,
        hide_map_index[hm] as_bool: false,
        inline_map_key[ik] as_bool: true,
        inline_array[ia] as_bool: true,
        inline_map[im] as_bool: true,
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::extract(&JsonValue::Null)
    }
}

fn main() -> Result<()> {
    let settings: Settings = if let Some(s) = std::env::args().nth(1) {
        let overrides = json::parse(&s).map_err(|e| {
            eprintln!(
                "Failed to parse input: {s}\n\
                Default settings:\n\
                {}",
                Settings::default().to_value().pretty(2),
            );
            eprintln!("\nKeys:");
            for (names, kind, default) in Settings::extract_info() {
                eprintln!(
                    "- {:25} {kind} = {default}",
                    format!("{}:", names.iter().format(", "))
                );
            }
            e
        })?;
        Settings::extract(&overrides)
    } else {
        Settings::default()
    };

    let mut current_key: Vec<u8> = Vec::with_capacity(kilobytes(1));
    write!(current_key, "root")?;

    let mut w = BufWriter::new(std::io::stdout(), megabytes(1))?;
    let mut stream = go(std::io::stdin());
    let stream = &mut stream;

    macro_rules! try_io_err {
        ($res:expr) => {
            match $res {
                Ok(_) => (),
                Err(e)
                    if e.as_io_err()
                        .map(|e| e.is_broken_pipe() || e.is_unexpected_eof())
                        .unwrap_or_default() =>
                {
                    return Ok(());
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        };
    }

    loop {
        let res = run(&settings, &mut w, &mut stream.multipeek(), &mut current_key);
        try_io_err!(w.flush());
        try_io_err!(res);
    }
}

#[derive(Debug)]
pub enum MsgpackType {
    Unknown,
    Str,
    Unsigned,
    Signed,
    Map,
    Array,
    Nil,
    True,
    False,
    Float,
    Bin,
    Ext,
}

impl MsgpackType {
    pub fn has_children(&self) -> bool {
        matches!(self, MsgpackType::Map | MsgpackType::Array)
    }
    pub fn is_array(&self) -> bool {
        matches!(self, MsgpackType::Array)
    }
    pub fn is_map(&self) -> bool {
        matches!(self, MsgpackType::Map)
    }
}

impl Default for MsgpackType {
    fn default() -> Self {
        Self::Unknown
    }
}

#[inline]
fn read_be_length(mut r: impl Read, count: usize) -> Result<usize> {
    ensure!(count <= 8);
    let mut b = [0u8; 8];
    r.read_exact(&mut b[(8 - count)..])?;
    Ok(usize::from_be_bytes(b))
}

#[inline]
pub fn try_exact_slice<T>(s: &[T], count: usize) -> Result<&[T]> {
    let r = &s[..count];
    ensure!(r.len() == count);
    Ok(r)
}

#[inline]
pub fn exact_slice<T>(s: &[T], count: usize) -> &[T] {
    let r = &s[..count];
    assert_eq!(r.len(), count);
    r
}

#[derive(Debug, Default)]
pub struct MsgPackInfo {
    // pub struct MsgPackInfo<'a> {
    tag: MsgpackType,
    extra_byte_count: usize,
    // utf8: Option<&'a str>,
    // bytes: Option<Bytes<'a, R>>,
    bytes: Option<Vec<u8>>,
    // bytes: Option<&'a [u8]>,
    map_count: usize,
    array_count: usize,
    ext_type: u8,
    unsigned_value: u64,
    signed_value: i64,
    float_value: f64,
}

pub fn read_byte_array<'a, R: Read>(br: &'_ mut BufReader<R>, count: usize) -> Result<Vec<u8>> {
    let mut vbuf = Vec::with_capacity(count);
    let mut remaining = count;
    while remaining > 0 {
        let buf = br.fill_buf()?;
        let to_take = buf.len().min(remaining);
        vbuf.extend(&buf[..to_take]);
        remaining -= to_take;
        br.consume(to_take);
    }
    Ok(vbuf)
}

fn read_info<R: Read>(mut r: &mut BufReader<R>) -> Result<MsgPackInfo> {
    let mut tag: [u8; 1] = [0u8];
    r.read_exact(&mut tag)?;
    let byte = tag[0];
    let mut info = MsgPackInfo::default();
    info.tag = match byte {
        0x00..=0x7f => {
            info.unsigned_value = byte as u64;
            MsgpackType::Unsigned
        }
        0x80..=0x8f => {
            info.map_count = (byte & 0xF) as usize;
            MsgpackType::Map
        }
        0x90..=0x9f => {
            info.array_count = (byte & 0xF) as usize;
            MsgpackType::Array
        }
        0xa0..=0xbf => {
            let length = (byte & 0x1F) as usize;
            info.bytes = Some(read_byte_array(&mut r, length)?);
            MsgpackType::Str
        }
        0xc0 => MsgpackType::Nil,
        0xc1 => MsgpackType::Unknown,
        0xc2 => MsgpackType::False,
        0xc3 => MsgpackType::True,
        0xc4 | 0xc5 | 0xc6 => {
            info.extra_byte_count = 1 << (byte - 0xc4);
            let length = read_be_length(&mut r, info.extra_byte_count)?;
            info.bytes = Some(read_byte_array(&mut r, length)?);
            MsgpackType::Bin
        }
        0xc7 | 0xc8 | 0xc9 => {
            info.extra_byte_count = 1 << (byte - 0xc7);
            let length = read_be_length(&mut r, info.extra_byte_count)?;
            let mut b = [0u8];
            r.read_exact(&mut b)?;
            info.ext_type = b[0];
            info.bytes = Some(read_byte_array(&mut r, length)?);
            MsgpackType::Ext
        }
        0xca => {
            let mut buf = [0u8; 4];
            info.extra_byte_count = 4;
            r.read_exact(&mut buf)?;
            info.float_value = f32::from_be_bytes(buf) as f64;
            MsgpackType::Float
        }
        0xcb => {
            let mut buf = [0u8; 8];
            info.extra_byte_count = 8;
            r.read_exact(&mut buf)?;
            info.float_value = f64::from_be_bytes(buf);
            MsgpackType::Float
        }
        0xcc | 0xcd | 0xce | 0xcf => {
            info.extra_byte_count = 1 << (byte - 0xcc);
            info.unsigned_value = read_be_length(&mut r, info.extra_byte_count)? as u64;
            MsgpackType::Unsigned
        }
        0xd0 | 0xd1 | 0xd2 | 0xd3 => {
            info.extra_byte_count = 1 << (byte - 0xd0);
            info.signed_value = read_be_length(&mut r, info.extra_byte_count)? as i64;
            MsgpackType::Signed
        }
        0xd4 | 0xd5 | 0xd6 | 0xd7 | 0xd8 => {
            let mut b = [0u8];
            r.read_exact(&mut b)?;
            info.ext_type = b[0];
            info.bytes = Some(read_byte_array(&mut r, 1 << (byte - 0xd4))?);
            MsgpackType::Ext
        }
        0xd9 | 0xda | 0xdb => {
            info.extra_byte_count = 1 << (byte - 0xd9);
            let length = read_be_length(&mut r, info.extra_byte_count)?;
            info.bytes = Some(read_byte_array(&mut r, length)?);
            MsgpackType::Str
        }
        0xdc | 0xdd => {
            info.extra_byte_count = 1 << (1 + byte - 0xdc);
            info.array_count = read_be_length(&mut r, info.extra_byte_count)?;
            MsgpackType::Array
        }
        0xde | 0xdf => {
            info.extra_byte_count = 1 << (1 + byte - 0xde);
            info.map_count = read_be_length(&mut r, info.extra_byte_count)?;
            MsgpackType::Map
        }
        0xe0..=0xff => {
            info.signed_value = byte as i8 as i64;
            MsgpackType::Signed
        }
    };
    Ok(info)
}

fn try_write_as_str(w: &mut impl Write, bytes: &[u8]) -> Result<()> {
    Ok(if let Ok(s) = std::str::from_utf8(bytes) {
        write!(w, "{s:?}")?;
    } else {
        for b in bytes {
            write!(w, "{b:02X}")?;
        }
    })
}

fn write_value(w: &mut impl Write, data: &MsgPackInfo) -> Result<()> {
    let bits = data.extra_byte_count * 8;
    match data.tag {
        MsgpackType::Str => {
            let bytes = data.bytes.as_ref().into_anyhow("No bytes for str")?;
            write!(w, "s{bits}")?;
            try_write_as_str(w, bytes)?;
        }
        MsgpackType::Unsigned => {
            write!(w, "{}u{bits}", data.unsigned_value)?;
        }
        MsgpackType::Signed => {
            write!(w, "{}i{bits}", data.unsigned_value)?;
        }
        MsgpackType::Float => {
            write!(w, "{}f{bits}", data.float_value)?;
        }
        MsgpackType::Array => {
            write!(w, "[]a{bits}@{}", data.array_count)?;
        }
        MsgpackType::Map => {
            write!(w, "{{}}m{bits}@{}", data.map_count)?;
        }
        MsgpackType::True => {
            w.write_all(b"true")?;
        }
        MsgpackType::False => {
            w.write_all(b"false")?;
        }
        MsgpackType::Nil => {
            w.write_all(b"nil")?;
        }
        MsgpackType::Bin => {
            let bytes = data.bytes.as_ref().into_anyhow("No bytes for bin")?;
            write!(w, "bin{bits}@{}(", bytes.len())?;
            try_write_as_str(w, bytes)?;
            w.write_all(b")")?;
        }
        MsgpackType::Ext => {
            let bytes = data.bytes.as_ref().into_anyhow("No bytes for bin")?;
            write!(w, "ext{bits}T{}@{}(", data.ext_type, bytes.len())?;
            try_write_as_str(w, bytes)?;
            w.write_all(b")")?;
        }
        MsgpackType::Unknown => {
            w.write_all(b"?unknown?")?;
        }
    }
    Ok(())
}

fn run(
    settings: &Settings,
    w: &mut impl Write,
    stream: &mut MultiPeek<impl Iterator<Item = Result<MsgPackInfo>>>,
    key: &mut Vec<u8>,
) -> Result<()> {
    let Some(data) = stream.next() else { return Ok(()) };
    let data = data?;
    let starting_key_length = key.len();
    w.write_all(key)?;
    write!(w, " = ")?;
    stream.reset_peek();
    match data.tag {
        MsgpackType::Array => {
            if data.array_count > 0
                && settings.inline_array
                && (|| -> anyhow::Result<bool> {
                    Ok({
                        for _ in 0..data.array_count {
                            let e = stream.peek().into_anyhow("Expected child")?;
                            let e = e.as_ref().into_anyhow("")?;
                            if e.array_count > 0 || e.map_count > 0 {
                                return Ok(false);
                            }
                        }
                        true
                    })
                })()?
            {
                w.write_all(b"[")?;
                write_value(w, &stream.next().unwrap()?)?;
                for _ in 1..data.array_count {
                    w.write_all(b", ")?;
                    write_value(w, &stream.next().unwrap()?)?;
                }
                write!(w, "]a{}@{}\n", data.extra_byte_count, data.array_count)?;
            } else {
                stream.reset_peek();
                write_value(w, &data)?;
                w.write_all(b"\n")?;
                for idx in 0..data.array_count {
                    if settings.hide_array_index {
                        key.write_all(b"[]")?;
                    } else {
                        write!(key, "[{idx}]")?;
                    }
                    run(settings, w, stream, key)?;
                    key.truncate(starting_key_length);
                }
            }
        }
        MsgpackType::Map => {
            if data.map_count > 0
                && settings.inline_map
                && (|| -> anyhow::Result<bool> {
                    Ok({
                        for _ in 0..(data.map_count * 2) {
                            let e = stream.peek().into_anyhow("Expected child")?;
                            let e = e.as_ref().into_anyhow("")?;
                            if e.array_count > 0 || e.map_count > 0 {
                                return Ok(false);
                            }
                        }
                        true
                    })
                })()?
            {
                w.write_all(b"{")?;
                write_value(w, &stream.next().unwrap()?)?;
                w.write_all(b" = ")?;
                write_value(w, &stream.next().unwrap()?)?;
                for _ in 1..data.map_count {
                    w.write_all(b", ")?;
                    write_value(w, &stream.next().unwrap()?)?;
                    w.write_all(b" = ")?;
                    write_value(w, &stream.next().unwrap()?)?;
                }
                write!(w, "}}m{}@{}\n", data.extra_byte_count, data.map_count)?;
            } else {
                stream.reset_peek();
                write_value(w, &data)?;
                w.write_all(b"\n")?;
                for idx in 0..data.map_count {
                    let inlined = if settings.inline_map_key {
                        let key_data = stream
                            .peek()
                            .into_anyhow("No key")?
                            .as_ref()
                            .into_anyhow("")?;
                        if !matches!(key_data.tag, MsgpackType::Map | MsgpackType::Array) {
                            key.write_all(b"{")?;
                            write_value(key, key_data)?;
                            key.write_all(b"}")?;
                            let _ = stream.next();
                            run(settings, w, stream, key)?;
                            key.truncate(starting_key_length);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !inlined {
                        if settings.hide_map_index {
                            key.write_all(b"{}")?;
                        } else {
                            write!(key, "{{{idx}}}")?;
                        }
                        let child_key_prefixed_length = key.len();
                        key.write_all(b".key")?;
                        run(settings, w, stream, key)?;
                        key.truncate(child_key_prefixed_length);
                        key.write_all(b".value")?;
                        run(settings, w, stream, key)?;
                        key.truncate(starting_key_length);
                    }
                }
            }
        }
        _ => {
            write_value(w, &data)?;
            w.write_all(b"\n")?;
        }
    }
    key.truncate(starting_key_length);
    Ok(())
}

fn go<R: Read>(r: R) -> impl Iterator<Item = Result<MsgPackInfo>> {
    let mut r = BufReader::new(r, megabytes(1)).unwrap();
    r.fill_buf().unwrap();
    std::iter::from_fn(move || Some(read_info(&mut r)))
}

#[allow(dead_code)]
pub const fn kilobytes(x: usize) -> usize {
    x * 1024
}

#[allow(dead_code)]
pub const fn megabytes(x: usize) -> usize {
    kilobytes(x) * 1024
}

#[allow(dead_code)]
pub const fn gigabytes(x: usize) -> usize {
    megabytes(x) * 1024
}

pub trait OptionExt {
    type Output;
    /// Empty string implies no prefix
    fn into_anyhow(self, prefix: &'static str) -> anyhow::Result<Self::Output>;
}

impl<T> OptionExt for Option<T> {
    type Output = T;
    fn into_anyhow(self, prefix: &'static str) -> anyhow::Result<T> {
        self.ok_or_else(|| {
            if !prefix.is_empty() {
                anyhow::anyhow!("{prefix}: {} was None", std::any::type_name::<Option<T>>())
            } else {
                anyhow::anyhow!("{} was None", std::any::type_name::<Option<T>>())
            }
        })
    }
}

pub trait ResultLog {
    type Output;
    fn into_anyhow(self, prefix: &'static str) -> anyhow::Result<Self::Output>;
}

impl<T, E> ResultLog for Result<T, E>
where
    E: std::fmt::Debug,
{
    type Output = T;
    fn into_anyhow(self, prefix: &'static str) -> anyhow::Result<T> {
        self.map_err(|err| {
            if !prefix.is_empty() {
                anyhow::anyhow!("{prefix}: {err:?}")
            } else {
                anyhow::anyhow!("{err:?}")
            }
        })
    }
}

trait ErrorExt {
    fn is_broken_pipe(&self) -> bool {
        self.as_io_err()
            .map(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
            .unwrap_or_default()
    }
    fn is_unexpected_eof(&self) -> bool {
        self.as_io_err()
            .map(|e| e.kind() == std::io::ErrorKind::UnexpectedEof)
            .unwrap_or_default()
    }
    fn as_io_err(&self) -> Option<&std::io::Error>;
}

impl ErrorExt for anyhow::Error {
    fn as_io_err(&self) -> Option<&std::io::Error> {
        self.downcast_ref()
    }
}

impl ErrorExt for std::io::Error {
    fn as_io_err(&self) -> Option<&std::io::Error> {
        Some(self)
    }
}
