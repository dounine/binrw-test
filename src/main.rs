use std::fs;
use std::io::Cursor;
use binrw::{BinRead, BinReaderExt, binrw};

#[binrw]
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
enum FileType {
    #[br(magic = 0x1u32)]
    MachObject,
    #[br(magic = 0x2u32)]
    MachExecute,
    #[br(magic = 0x3u32)]
    MachFVMLib,
    #[br(magic = 0x4u32)]
    MachCore,
    #[br(magic = 0x5u32)]
    MachPreload,
    #[br(magic = 0x6u32)]
    MachDyLib,
    #[br(magic = 0x7u32)]
    MachDyLinker,
    #[br(magic = 0x8u32)]
    MachBundle,
    #[br(magic = 0x9u32)]
    MachDyLibStub,
    #[br(magic = 0xau32)]
    MachDsym,
    #[br(magic = 0xbu32)]
    MachKextBundle,
    Unknown(u32),
}

pub type CpuType = i32;
pub type CpuSubtype = i32;


#[binrw]
#[derive(Debug)]
pub struct MachHeader {
    pub magic: MachType,// mach magic 标识符，用来确定其属于 64位 还是 32位
    pub cpu_type: CpuType,//CPU 类型标识符，同通用二进制格式中的定义
    pub cpu_subtype: CpuSubtype,//CPU 子类型标识符，同通用二级制格式中的定义
    pub file_type: FileType,//文件类型，主要用来区分可执行文件、动态库、静态库等
    pub n_cmds: u32,//加载器中加载命令(Load commands)的数量
    pub size_of_cmds: u32,//加载器中加载命令的总字节大小
    pub flags: u32, // 标志位，主要用来表示是否是64位的二进制文件，是否是可执行文件等
    #[br(if (magic == MachType::MachoMagic || magic == MachType::MachoMagic64))]
    pub reserved: u32,// 64 位的保留字段
}


fn main() {
    let data = fs::read("./data/ios").unwrap();
    let mut reader = Cursor::new(data);
    let macho = MachHeader::read_ne(&mut reader).unwrap();

    println!("{:?}", macho);
}
