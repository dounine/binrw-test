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

pub type CpuType = i32;
pub type CpuSubtype = i32;

#[binrw]
#[derive(Debug)]
pub struct MachHeader {
    pub magic: MachType,
    /* mach magic 标识符，用来确定其属于 64位 还是 32位 */
    pub cpu_type: CpuType,
    /* CPU 类型标识符，同通用二进制格式中的定义 */
    pub cpu_subtype: CpuSubtype,
    /* CPU 子类型标识符，同通用二级制格式中的定义 */
    pub file_type: u32,
    /* 文件类型 */
    pub n_cmds: u32,
    /* 加载器中加载命令(Load commands)的数量 */
    pub size_of_cmds: u32,
    /* 加载器中加载命令的总字节大小 */
    pub flags: u32,
    /* dyld 的标志，主要与系统的加载、链接有关 */
    #[br(if (magic == MachType::MachoMagic || magic == MachType::MachoMagic64))]
    pub reserved: u32,
    /* 64 位的保留字段 */
}


fn main() {
    let data = fs::read("./data/ios").unwrap();
    let mut reader = Cursor::new(data);
    let macho = MachHeader::read_ne(&mut reader).unwrap();

    println!("{:?}", macho);
}
