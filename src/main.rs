use anyhow::{ensure, Result};
// use next_gen::generator_fn::GeneratorFn;
use next_gen::prelude::*;
// use smol::{future::poll_once, pin};
// use std::future::Future;
use itertools::structs::MultiPeek;
use itertools::Itertools;
use std::io::{BufRead, Read, Write};
// use std::iter::Peekable;
use miniserde::{json, Deserialize, Serialize};
use vmap::io::{BufReader, BufWriter};

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

impl MsgpackType {
    pub fn parts(&self) -> (&'static str, &'static str) {
        match self {
            Self::Unknown => ("???", ""),
            Self::Str => ("s", ""),
            Self::Unsigned => ("", "u"),
            Self::Signed => ("", "i"),
            Self::Map => ("{", "}"),
            Self::Array => ("[", "]"),
            Self::Nil => ("nil", ""),
            Self::True => ("true", ""),
            Self::False => ("false", ""),
            Self::Float => ("", "f"),
            Self::Bin => ("bin", ""),
            Self::Ext => ("ext", ""),
        }
    }
}

// struct MsgpackClassification {
//     kind: MsgpackType,
//     variable_length: i64,
//     length: i64,
//     value: i64,
// }

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

// impl Default for MsgPackInfo<'_> {
//     fn default() -> Self {
//         Self {
//             tag: MsgpackType::default(),
//             extra_byte_count: 0,
//             bytes: None,
//             map_count: 0,
//             array_count: 0,
//             ext_type: 0,
//             unsigned_value: 0,
//             signed_value: 0,
//         }
//     }
// }

// mod sealed_499e3f0fd282409191b7d2391a6d4c17 {
//     use super::*;
//     // pub struct DelayedConsume<R: Read>(BufReader<R>, usize);

//     // impl<R: Read> AsRef<[u8]> for DelayedConsume<R> {
//     //     fn as_ref(&self) -> &[u8] {
//     //         &self.0.buffer()[..self.1]
//     //     }
//     // }

//     // impl<R: Read> DelayedConsume<R> {
//     //     pub fn new(r: BufReader<R>, count: usize) -> Result<Self> {
//     //         ensure!(r.buffer().len() >= count);
//     //         Ok(Self(r, count))
//     //     }

//     //     pub fn into_inner(self) -> BufReader<R> {
//     //         self.0.consume(self.1);
//     //         self.0
//     //     }
//     // }

//     pub struct DelayedConsume<'a, R: Read>(&'a mut BufReader<R>, usize);

//     impl<R: Read> AsRef<[u8]> for DelayedConsume<'_, R> {
//         fn as_ref(&self) -> &[u8] {
//             &self.0.buffer()[..self.1]
//         }
//     }

//     impl<R: Read> DelayedConsume<'_, R> {
//         pub fn new(r: &mut BufReader<R>, count: usize) -> Result<Self> {
//             ensure!(r.buffer().len() >= count);
//             Ok(Self(r, count))
//         }
//     }

//     impl<R: Read> Drop for DelayedConsume<'_, R> {
//         fn drop(&mut self) {
//             self.0.consume(self.1);
//         }
//     }
// }
// pub use sealed_499e3f0fd282409191b7d2391a6d4c17::*;

// pub enum Bytes<'a, R: Read> {
//     DelayedConsume(DelayedConsume<'a, R>),
//     // BufReader(&'a BufReader<R>, usize),
//     Slice(&'a [u8]),
// }

// impl<R: Read> AsRef<[u8]> for Bytes<'_, R> {
//     fn as_ref(&self) -> &[u8] {
//         match self {
//             Self::DelayedConsume(b) => b.as_ref(),
//             // Self::BufReader(b, count) => &b.buffer()[..count],
//             Self::Slice(b) => b.as_ref(),
//         }
//     }
// }

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

// pub fn read_byte_array<'a, R: Read>(
//     br: &'_ mut BufReader<R>,
//     vbuf: &'a mut Vec<u8>,
//     count: usize,
//     // to_consume: &mut usize,
// ) -> Result<&'a [u8]> {
//     vbuf.clear();
//     // let buf = br.fill_buf()?;
//     // if buf.len() >= count {
//     //     *to_consume += count;
//     //     Ok(&br.buffer()[..count])
//     // } else {
//     // }
//     let mut remaining = count;
//     while remaining > 0 {
//         let buf = br.fill_buf()?;
//         let to_take = buf.len().min(remaining);
//         vbuf.extend(&buf[..to_take]);
//         remaining -= to_take;
//         br.consume(to_take);
//     }
//     Ok(vbuf.as_slice())
// }

fn read_info<R: Read>(mut r: &mut BufReader<R>) -> Result<MsgPackInfo> {
    let mut tag: [u8; 1] = [0u8];
    r.read_exact(&mut tag)?;
    let byte = tag[0];
    let mut info = MsgPackInfo::default();
    // dbg!(classifier(byte));
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
            // info.extra_byte_count = 1 << (byte - 0xd4);
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

#[generator(yield(Result<MsgPackInfo>))]
// #[generator(yield(MsgPackInfo<'_>))]
pub fn go<R: Read>(r: R) {
    let mut r = BufReader::new(r, megabytes(1)).unwrap();
    r.fill_buf().unwrap();

    // let mut extended_buffer: Vec<u8> = Vec::with_capacity(megabytes(4));
    loop {
        yield_!(read_info(&mut r));
    }
}

// macro_rules! next {
//     ($label:tt: $gen:ident$(($with:expr))?) => {
//         match $gen.as_mut().resume(($($with)?)) {
//             GeneratorState::Yielded(v) => v,
//             GeneratorState::Returned(r) => break $label r,
//         }
//     };
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct Settings {
    pub hide_array_index: bool,
    pub hide_obj_index: bool,
    pub inline_obj_key: bool,
    pub inline_array: bool,
    pub inline_map: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            hide_array_index: false,
            hide_obj_index: false,
            inline_obj_key: true,
            inline_array: true,
            inline_map: true,
        }
    }
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
                    let inlined = if settings.inline_obj_key {
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
                        if settings.hide_obj_index {
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

fn main() -> Result<()> {
    let settings: Settings = if let Some(s) = std::env::args().nth(1) {
        json::from_str(&s).map_err(|e| {
            eprintln!(
                "Failed to parse input: {s}\n\
                Default arguments:\n\
                {}",
                json::to_string(&<Settings as Default>::default())
                    .replace(",", ",\n  ")
                    .replace("{", "{\n  ")
                    .replace("}", "\n}")
            );
            e
        })?
    } else {
        Default::default()
    };
    // pub struct ObjectContext {
    //     count: usize,
    //     index: usize,
    //     is_array: bool,
    //     existing_key_length: usize,
    // }
    // // let mut obj_stack: Vec<(MsgPackInfo, usize)> = vec![];
    // let mut obj_stack: Vec<ObjectContext> = vec![];

    let mut current_key: Vec<u8> = Vec::with_capacity(kilobytes(1));
    // let mut key_stack: Vec<usize> = vec![];
    // macro_rules! pop_key {
    //     () => {
    //         current_key.truncate(key_stack.pop().into_anyhow("key_stack")?);
    //     };
    // }
    // macro_rules! push_key {
    //     () => {
    //         key_stack.push(current_key.len());
    //     };
    // }
    // push_key!();
    write!(current_key, "root")?;

    let mut w = BufWriter::new(std::io::stdout(), megabytes(1))?;
    mk_gen!(let mut stream = go(std::io::stdin()));

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
        let res = run(
            &settings,
            &mut w,
            &mut stream.as_mut().multipeek(),
            // &mut stream.as_mut().peekable(),
            &mut current_key,
        );
        try_io_err!(w.flush());
        try_io_err!(res);
    }
    // Ok(())

    // macro_rules! next {
    //   ($label:tt: $gen:ident$(($with:expr))?) => {
    //       match $gen.as_mut().resume(($($with)?)) {
    //           GeneratorState::Yielded(v) => v,
    //           GeneratorState::Returned(r) => break $label r,
    //       }
    //   };
    // }

    // // gen_iter! {
    // //     for data in (&mut stream) {
    // 'outer: loop {
    //     let data = next!('outer: stream);
    //     // let (prefix, suffix) = data.tag.parts();
    //     // if !prefix.is_empty() {
    //     //     write!(w, "{prefix}{}", data.extra_byte_count)?;
    //     // }
    //     obj_stack.pop()
    //     if let Some(ctx) = obj_stack.last_mut() {
    //         if
    //         assert!(ctx.count > 0);
    //         let idx = ctx.index;
    //         ctx.index += 1;
    //         push_key!();
    //         if ctx.is_array {
    //             if hide_array_index {
    //                 write!(current_key, "[]")?;
    //             } else {
    //                 write!(current_key, "[{idx}]")?;
    //             }
    //         } else {
    //             write!(current_key, "{{{idx}}}")?;
    //         }
    //         if ctx.index >= ctx.count {
    //             obj_stack.pop();
    //             pop_key!();
    //         } else {
    //             1
    //         }
    //     } else {
    //         0
    //     };
    //     w.write_all(&current_key)?;
    //     write!(w, " = ")?;
    //     match data.tag {
    //         MsgpackType::Str => {
    //             let bytes = data.bytes.into_anyhow("No bytes for str")?;
    //             if let Ok(s) = std::str::from_utf8(&bytes) {
    //                 write!(w, "s{}{s:?}\n", data.extra_byte_count)?;
    //             } else {
    //                 write!(w, "s{}{bytes:?}\n", data.extra_byte_count)?;
    //             }
    //         }
    //         MsgpackType::Unsigned => {
    //             write!(w, "{}u{}", data.unsigned_value, data.extra_byte_count)?;
    //         }
    //         MsgpackType::Signed => {
    //             write!(w, "{}i{}", data.unsigned_value, data.extra_byte_count)?;
    //         }
    //         MsgpackType::Float => {
    //             write!(w, "{}f{}", data.float_value, data.extra_byte_count)?;
    //         }
    //         MsgpackType::Array => {
    //             push_key!();
    //             write!(w, "[]a{}x{}", data.extra_byte_count, data.array_count)?;
    //             obj_stack.push(ObjectContext {
    //                 count: data.array_count,
    //                 index: 0,
    //                 is_array: true,
    //                 existing_key_length: current_key.len(),
    //             });
    //             // write!(w, "{data:?}\n")?;
    //             // for _ in 0..data.array_count {
    //             //     let subdata = next!('outer: stream);
    //             //     write!(w, "{subdata:?}\n")?;
    //             // }
    //         }
    //         MsgpackType::Map => {
    //             push_key!();
    //             write!(w, "[]m{}x{}", data.extra_byte_count, data.map_count)?;
    //             obj_stack.push(ObjectContext {
    //                 count: data.map_count * 2,
    //                 index: 0,
    //                 is_array: false,
    //                 existing_key_length: current_key.len(),
    //             });
    //             // write!(w, "{data:?}\n")?;
    //             // for _ in 0..data.array_count {
    //             //     let subdata = next!('outer: stream);
    //             //     write!(w, "{subdata:?}\n")?;
    //             // }
    //         }
    //         _ => {
    //             write!(w, "{data:?}\n")?;
    //         }
    //     }
    //     // if !suffix.is_empty() {
    //     //     write!(w, "{suffix}{}", data.extra_byte_count)?;
    //     // }
    //     write!(w, "\n")?;
    //     for _ in 0..pop_count {
    //         pop_key!();
    //     }
    // }
    // }
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

// fn msgpack_classify(header: u8) -> MsgpackClassification {
//     use MsgpackType::*;
//     match header {
//         0xc0 => {
//             return MsgpackClassification {
//                 kind: Nil,
//                 length: 1,
//                 variable_length: 0,
//                 value: 0,
//             }
//         }
//         0xc2 => {
//             return MsgpackClassification {
//                 kind: False,
//                 length: 1,
//                 variable_length: 0,
//                 value: 0,
//             }
//         }
//         0xc3 => {
//             return MsgpackClassification {
//                 kind: True,
//                 length: 1,
//                 variable_length: 0,
//                 value: 1,
//             }
//         }
//         0xc4 | 0xc5 | 0xc6 => {
//             return MsgpackClassification {
//                 kind: Bin,
//                 length: 1 + (1 << (header - 0xc4)),
//                 variable_length: -1,
//                 value: 0,
//             }
//         }
//         0xc7 | 0xc8 | 0xc9 => {
//             return MsgpackClassification {
//                 kind: Ext,
//                 length: 1 + (1 << (header - 0xc7)),
//                 variable_length: -1,
//                 value: 0,
//             }
//         }
//         0xca | 0xcb => {
//             return MsgpackClassification {
//                 kind: Float,
//                 length: 1 + (1 << (header + 2 - 0xca)),
//                 variable_length: 0,
//                 value: 0,
//             }
//         }
//         0xcc | 0xcd | 0xce | 0xcf => {
//             return MsgpackClassification {
//                 kind: Posnum,
//                 length: 1 + (1 << (header - 0xcc)),
//                 variable_length: 0,
//                 value: 0,
//             }
//         }
//         0xd0 | 0xd1 | 0xd2 | 0xd3 => {
//             return MsgpackClassification {
//                 kind: Signum,
//                 length: 1 + (1 << (header - 0xd0)),
//                 variable_length: 0,
//                 value: 0,
//             }
//         }
//         0xd4 | 0xd5 | 0xd6 | 0xd7 | 0xd8 => {
//             return MsgpackClassification {
//                 kind: Fixext,
//                 length: 1 + 1 + (1 << (header - 0xd4)),
//                 variable_length: 0,
//                 value: 0,
//             }
//         }
//         0xd9 | 0xda | 0xdb => {
//             return MsgpackClassification {
//                 kind: Str,
//                 length: 1 + (1 << (header - 0xd9)),
//                 variable_length: -1,
//                 value: 0,
//             }
//         }
//         0xdc | 0xdd => {
//             return MsgpackClassification {
//                 kind: Array,
//                 length: 1 + (1 << (header + 1 - 0xdc)),
//                 variable_length: -1,
//                 value: 0,
//             }
//         }
//         0xde | 0xdf => {
//             return MsgpackClassification {
//                 kind: Map,
//                 length: 1 + (1 << (header + 1 - 0xde)),
//                 variable_length: -1,
//                 value: 0,
//             }
//         }
//         _ => match header >> 4 {
//             0x8 => {
//                 return MsgpackClassification {
//                     kind: Map,
//                     length: 1,
//                     variable_length: ((header & 0xF) as i64) << 1,
//                     value: 0,
//                 }
//             }
//             0x9 => {
//                 return MsgpackClassification {
//                     kind: Array,
//                     length: 1,
//                     variable_length: (header & 0xF) as i64,
//                     value: 0,
//                 }
//             }
//             _ => match header >> 5 {
//                 0x5 => {
//                     return MsgpackClassification {
//                         kind: Str,
//                         length: 1,
//                         variable_length: (header & 0x1F) as i64,
//                         value: 0,
//                     }
//                 }
//                 0x7 => {
//                     return MsgpackClassification {
//                         kind: Signum,
//                         length: 1,
//                         variable_length: 0,
//                         value: (header & 0x1F) as i64,
//                     }
//                 }
//                 _ => match header >> 7 {
//                     0 => {
//                         return MsgpackClassification {
//                             kind: Posnum,
//                             length: 1,
//                             variable_length: 0,
//                             value: header as i64,
//                         }
//                     }
//                     _ => {
//                         return MsgpackClassification {
//                             kind: Unknown,
//                             length: 1,
//                             variable_length: 0,
//                             value: 0,
//                         }
//                     }
//                 },
//             },
//         },
//     }
// }

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

// #[derive(Debug)]
// enum Classification {
//     PositiveFixint,
//     Fixmap,
//     Fixarray,
//     Fixstr,
//     Nil,
//     NeverUsed,
//     False,
//     True,
//     Bin8,
//     Bin16,
//     Bin32,
//     Ext8,
//     Ext16,
//     Ext32,
//     Float32,
//     Float64,
//     Uint8,
//     Uint16,
//     Uint32,
//     Uint64,
//     Int8,
//     Int16,
//     Int32,
//     Int64,
//     Fixext1,
//     Fixext2,
//     Fixext4,
//     Fixext8,
//     Fixext16,
//     Str8,
//     Str16,
//     Str32,
//     Array16,
//     Array32,
//     Map16,
//     Map32,
//     NegativeFixint,
//     Unknown,
// }

// fn classifier(byte: u8) -> (Classification, u8) {
//     match byte {
//         0x00..=0x7f => (Classification::PositiveFixint, 0),
//         0x80..=0x8f => (Classification::Fixmap, (byte & 0xF) << 1),
//         0x90..=0x9f => (Classification::Fixarray, byte & 0xF),
//         0xa0..=0xbf => (Classification::Fixstr, byte & 0x1F),
//         0xc0 => (Classification::Nil, 0),
//         0xc1 => (Classification::NeverUsed, 0),
//         0xc2 => (Classification::False, 0),
//         0xc3 => (Classification::True, 0),
//         0xc4 => (Classification::Bin8, 1),
//         0xc5 => (Classification::Bin16, 2),
//         0xc6 => (Classification::Bin32, 4),
//         0xc7 => (Classification::Ext8, 1),
//         0xc8 => (Classification::Ext16, 2),
//         0xc9 => (Classification::Ext32, 4),
//         0xca => (Classification::Float32, 4),
//         0xcb => (Classification::Float64, 8),
//         0xcc => (Classification::Uint8, 1),
//         0xcd => (Classification::Uint16, 2),
//         0xce => (Classification::Uint32, 4),
//         0xcf => (Classification::Uint64, 8),
//         0xd0 => (Classification::Int8, 1),
//         0xd1 => (Classification::Int16, 2),
//         0xd2 => (Classification::Int32, 4),
//         0xd3 => (Classification::Int64, 8),
//         0xd4 => (Classification::Fixext1, 1),
//         0xd5 => (Classification::Fixext2, 2),
//         0xd6 => (Classification::Fixext4, 4),
//         0xd7 => (Classification::Fixext8, 8),
//         0xd8 => (Classification::Fixext16, 16),
//         0xd9 => (Classification::Str8, 1),
//         0xda => (Classification::Str16, 2),
//         0xdb => (Classification::Str32, 4),
//         0xdc => (Classification::Array16, 2),
//         0xdd => (Classification::Array32, 4),
//         0xde => (Classification::Map16, 2),
//         0xdf => (Classification::Map32, 4),
//         0xe0..=0xff => (Classification::NegativeFixint, 0),
//         _ => (Classification::Unknown, 0),
//     }
// }

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
