use binrw::{binrw, BinRead, BinReaderExt, BinResult, BinWrite, BinWriterExt};
use std::fs;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::ptr::read;
#[binrw]
#[derive(Debug, PartialEq)]
enum MachType {
    #[brw(magic(0xcafebabeu32))]
    FatMaGic,
    #[brw(magic(0xbebafecau32))]
    FatCiGam,
    #[brw(magic(0xfeedfaceu32))]
    MachoMagic,
    #[brw(magic(0xfeedfacfu32))]
    MachoMagic64,
    #[brw(magic(0xcefaedfeu32))]
    MachoCiGam,
    #[brw(magic(0xcffaedfeu32))]
    MachoCiGam64,
    Unknown(u32),
}

#[binrw]
#[derive(Debug, PartialEq)]
enum FileType {
    #[brw(magic(0x1u32))]
    MachObject,
    #[brw(magic(0x2u32))]
    MachExecute,
    #[brw(magic(0x3u32))]
    MachFVMLib,
    #[brw(magic(0x4u32))]
    MachCore,
    #[brw(magic(0x5u32))]
    MachPreload,
    #[brw(magic(0x6u32))]
    MachDyLib,
    #[brw(magic(0x7u32))]
    MachDyLinker,
    #[brw(magic(0x8u32))]
    MachBundle,
    #[brw(magic(0x9u32))]
    MachDyLibStub,
    #[brw(magic(0xau32))]
    MachDsym,
    #[brw(magic(0xbu32))]
    MachKextBundle,
    Unknown(u32),
}

pub type CpuType = i32;
pub type CpuSubtype = i32;

#[binrw]
#[derive(Debug)]
pub struct MachHeader {
    magic: MachType,         // mach magic 标识符，用来确定其属于 64位 还是 32位
    cpu_type: CpuType,       //CPU 类型标识符，同通用二进制格式中的定义
    cpu_subtype: CpuSubtype, //CPU 子类型标识符，同通用二级制格式中的定义
    file_type: FileType,     //文件类型，主要用来区分可执行文件、动态库、静态库等
    //magic 等于 CIGMA则使用小端
    n_cmds: u32,       //加载器中加载命令(Load commands)的数量
    size_of_cmds: u32, //加载器中加载命令的总字节大小
    flags: u32,        // 标志位，主要用来表示是否是64位的二进制文件，是否是可执行文件等
    #[br(if(magic == MachType::MachoMagic64 || magic == MachType::MachoCiGam64))]
    #[bw(if(*magic == MachType::MachoMagic64 || *magic == MachType::MachoCiGam64))]
    reserved: u32, // 64 位的保留字段
}

fn main() {
    let data = fs::read("./data/ios").unwrap();
    let mut reader = Cursor::new(&data);
    let mut macho: MachHeader = reader.read_ne().unwrap();
    macho.cpu_type = 2;

    let mut writer = Cursor::new(vec![]);
    macho.write_le(&mut writer).unwrap();
    let mut file = File::create("./data/ios2").unwrap();
    writer.set_position(0);
    std::io::copy(&mut writer, &mut file).unwrap();

    let data = fs::read("./data/ios2").unwrap();
    let mut reader = Cursor::new(&data);
    let macho = MachHeader::read_ne(&mut reader).unwrap();
    println!("2 {:?}", macho);
    println!("length {:?}", data.len());
}
