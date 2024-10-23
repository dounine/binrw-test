use std::fs;
use std::io::Cursor;
use binrw::{BinRead, BinReaderExt, binrw};

#[binrw]
#[derive(Debug)]
enum MachType {
    #[br(magic = 0xcafebabeu32)]
    FatMaGic,
    #[br(magic = 0xbebafecau32)]
    FatCiGam,
    #[br(magic = 0xfeedfaceu32)]
    MachoMagic,
    #[br(magic = 0xfeedfacfu32)]
    MachoMagic64,
    #[br(magic = 0xcefaedfeu32)]
    MachoCiGam,
    #[br(magic = 0xcffaedfeu32)]
    MachoCiGam64,
    Unknown(u32),
}

#[binrw]
#[derive(Debug)]
struct Macho {
    magic: MachType,
}


fn main() {
    let data = fs::read("./data/ios").unwrap();
    let mut reader = Cursor::new(data);
    let macho = Macho::read_ne(&mut reader).unwrap();

    println!("{:?}", macho);
}
