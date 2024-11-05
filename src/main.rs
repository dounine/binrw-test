use binrw::{binrw, BinRead, BinReaderExt, BinResult, BinWrite, NullString};
use std::fs;
use std::fs::File;
use std::io::{Cursor, Read, SeekFrom};
use std::ops::Neg;

#[binrw]
#[brw(is_big = big_endian,import{big_endian: bool})]
#[derive(Debug, PartialEq, Eq)]
enum CpuType {
    #[brw(magic = 7_i32)]
    X86,
    #[brw(magic = 16777223_i32)]
    X86_64,
    #[brw(magic = 12_i32)]
    Arm,
    #[brw(magic = 16777228_i32)]
    Arm64,
    #[brw(magic = 33554444_i32)]
    Arm64_32,
    Unknown(i32),
}

#[binrw]
#[derive(Debug, PartialEq, Eq)]
enum CpuSubtype {
    #[brw(magic(6_i32))]
    ArmV6,
    #[brw(magic(9_i32))]
    ArmV7,
    #[brw(magic(11_i32))]
    ArmV7S,
    #[brw(magic(12_i32))]
    ArmV7K,
    #[brw(magic(13_i32))]
    ArmV8,
    #[brw(magic(0_i32))]
    Arm64All,
    #[brw(magic(1_i32))]
    Arm64V8,
    #[brw(magic(2_i32))]
    Arm64E,
    Unknown(i32),
}

#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
enum MachType {
    #[brw(magic(0xcafebabe_u32))]
    FatMaGic,
    #[brw(magic(0xbebafeca_u32))]
    FatCiGam,
    #[brw(magic(0xfeedface_u32))]
    MachoMagic,
    #[brw(magic(0xfeedfacf_u32))]
    MachoMagic64,
    #[brw(magic(0xcefaedfe_u32))]
    MachoCiGam,
    #[brw(magic(0xcffaedfe_u32))]
    MachoCiGam64,
    Unknown(u32),
}

#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileType {
    #[brw(magic(0x1_u32))]
    MachObject,
    #[brw(magic(0x2_u32))]
    MachExecute,
    #[brw(magic(0x3_u32))]
    MachFVMLib,
    #[brw(magic(0x4_u32))]
    MachCore,
    #[brw(magic(0x5_u32))]
    MachPreload,
    #[brw(magic(0x6_u32))]
    MachDyLib,
    #[brw(magic(0x7_u32))]
    MachDyLinker,
    #[brw(magic(0x8_u32))]
    MachBundle,
    #[brw(magic(0x9_u32))]
    MachDyLibStub,
    #[brw(magic(0xa_u32))]
    MachDsym,
    #[brw(magic(0xb_u32))]
    MachKextBundle,
    Unknown(u32),
}

#[binrw]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
enum CmdType {
    #[default]
    #[brw(magic(0x00000001_u32))]
    LcSegment,
    #[brw(magic(0x00000019_u32))]
    LcSegment64,
    #[brw(magic(0x00000021_u32))]
    LcEncryptionInfo,
    #[brw(magic(0x0000002c_u32))]
    LcEncryptionInfo64,
    #[brw(magic(0x0000001d_u32))]
    LcCodeSignature,
    Unknown(u32),
}
#[binrw]
#[derive(Debug)]
struct Section<T: for<'a> BinRead<Args<'a> = ()> + for<'a> BinWrite<Args<'a> = ()>> {
    section_name: [u8; 16], /* name of this section */
    segment_name: [u8; 16], /* segment this section goes in */
    addr: T,                /* memory address of this section */
    size: T,                /* size in bytes of this section */
    offset: u32,            /* file offset of this section */
    align: u32,             /* section alignment (power of 2) */
    rel_offset: u32,        /* file offset of relocation entries */
    nreloc: u32,            /* number of relocation entries */
    flags: u32,             /* flags (section type and attributes)*/
    reserved1: u32,         /* reserved */
    reserved2: u32,         /* reserved */
    reserved3: Option<u32>,
}
#[binrw]
#[derive(Debug)]
#[brw(little)]
struct Data {
    version: u16,
    #[br(temp)]
    #[bw(calc = items.len().try_into().unwrap())]
    num_items: u32,
    #[br(args{ count: 10, inner: (true,) })]
    items: Vec<Item>,
}

#[binrw]
#[derive(Debug)]
#[brw(little)]
#[br(import(version: bool))]
struct Item {
    field1: u32,
    #[br(if(version, 0))]
    field2: u64,
}
#[binrw]
#[derive(Debug)]
enum LoadCommand {
    #[brw(magic = 0x00000001_u32)]
    Segment {
        cmd_size: u32,
        segment_name: [u8; 16], /* segment name */
        vm_addr: u32,           /* memory address of this segment */
        vm_size: u32,           /* memory size of this segment */
        file_offset: u32,       /* file offset of this segment */
        file_size: u32,         /* amount to map from the file */
        max_prot: i32,          /* maximum VM protection */
        init_prot: i32,         /* initial VM protection */
        #[br(temp)]
        #[bw(calc = sections.len().try_into().unwrap())]
        nsects: u32, /* number of sections in segment */
        flags: u32,             /* flags */
        #[br(count = nsects)]
        sections: Vec<Section<u32>>,
    },
    #[brw(magic = 0x00000019_u32)]
    Segment64 {
        cmd_size: u32,
        segment_name: [u8; 16],
        vm_addr: u64,
        vm_size: u64,
        file_offset: u64,
        file_size: u64,
        max_prot: i32,
        init_prot: i32,
        #[br(temp)]
        #[bw(calc = sections.len().try_into().unwrap())]
        nsects: u32,
        flags: u32,
        #[br(count = nsects)]
        sections: Vec<Section<u64>>,
    },
    #[brw(magic = 0x00000021_u32)]
    EncryptionInfo {
        cmd_size: u32,
        file_offset: u32,
        file_size: u32,
    },
    #[brw(magic = 0x0000002c_u32)]
    EncryptionInfo64 {
        cmd_size: u32,
        file_offset: u32,
        file_size: u32,
        crypt_id: u32,
        padding: u32,
    },
    #[brw(magic = 0x0000001d_u32)]
    CodeSignature {
        cmd_size: u32,
        file_offset: u32,
        file_size: u32,
    },
    Unknown {
        cmd: CmdType,
        #[bw(calc = (data.len() + 8) as u32)]
        cmd_size: u32,
        #[br(count = cmd_size - 8)]
        data: Vec<u8>,
    },
}

#[binrw]
#[br(import{ cmd_size:u32 })]
#[derive(Debug, Default)]
struct CommandInfo {
    #[br(count = cmd_size )]
    data: Vec<u8>,
}

#[binrw]
#[derive(Debug)]
pub struct MachHeader {
    magic: MachType, // mach magic 标识符，用来确定其属于 64位 还是 32位
    #[br(seek_before = SeekFrom::Current(-4),map = |magic:MachType| matches!(magic,MachType::MachoCiGam|MachType::MachoCiGam64))]
    #[bw(ignore)]
    big_endian: bool,
    #[br(seek_before = SeekFrom::Current(-4),map = |magic:MachType| matches!(magic,MachType::MachoMagic64|MachType::MachoCiGam64))]
    #[bw(ignore)]
    bit_64: bool, //是否是64位的二进制文件

    #[brw( args { big_endian: big_endian.clone() } )]
    cpu_type: CpuType, //CPU 类型标识符，同通用二进制格式中的定义
    cpu_subtype: CpuSubtype, //CPU 子类型标识符，同通用二级制格式中的定义
    file_type: FileType,     //文件类型，主要用来区分可执行文件、动态库、静态库等
    #[br(is_big = big_endian )]
    count_of_cmds: u32, //加载器中加载命令(Load commands)的数量
    #[br(is_big = big_endian )]
    size_of_cmds: u32, //加载器中加载命令的总字节大小
    flags: u32,              // 标志位，主要用来表示是否是64位的二进制文件，是否是可执行文件等
    // #[brw(if(bit_64.clone()))]
    #[br(try)]
    reserved: Option<u32>, // 64 位的保留字段

    #[br(count = count_of_cmds)]
    commands: Vec<LoadCommand>,
}

#[binrw]
struct SegmentCommand64 {
    pub segment_name: [u8; 16], /* segment name */
    pub vm_addr: u64,           /* memory address of this segment */
    pub vm_size: u64,           /* memory size of this segment */
    pub file_offset: u64,       /* file offset of this segment */
    pub file_size: u64,         /* amount to map from the file */
    pub max_prot: i32,          /* maximum VM protection */
    pub init_prot: i32,         /* initial VM protection */
    pub nsects: u32,            /* number of sections in segment */
    pub flags: u32,             /* flags */
}
#[cfg(test)]
mod tests {
    use binrw::{binrw, BinReaderExt, BinResult, BinWrite};
    use std::io::{Cursor, Read, SeekFrom};

    // #[binrw::parser]
    // fn bool_reader(reader: &mut dyn Read, is_big: bool) -> BinResult<bool> {
    //
    // }

    #[test]
    fn test_read() {
        #[binrw]
        #[derive(Debug)]
        struct Example {
            first: u32,

            #[br(seek_before = SeekFrom::Current(-4),map = |val:u32| val > 0)]
            #[bw(ignore)]
            second: bool,

            #[brw(align_after = 16)]
            data: u32,
            // #[br(temp)]
            // #[bw(calc = *value)]
            // temp_value: u32,
            //
            // // #[brw(ignore)]
            // #[br(seek_before = SeekFrom::Current(8))]
            // #[bw(ignore)]
            // is_big_endian: u32,
            //
            // #[bw(ignore)]
            // #[br(seek_before = SeekFrom::Current(4))]
            // ignore_value: u32,
            //
            // #[brw(big)]
            // value: u32,
            //
            // #[br(align_after = 16)]
            // total_resource_count: u32,
        }
        let input_data: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, // temp_value
            0x02, 0x00, 0x00, 0x00, // ignored_value
            0x04, 0x00, 0x00, 0x00, // value
            0x00, 0x00, 0x00, 0x00, //align
        ];
        let mut reader = Cursor::new(input_data);
        let mut example: Example = reader.read_le().unwrap();
        println!("{:?}", example);
        example.first = 3;
        example.second = true;
        let mut writer = Cursor::new(vec![]);
        example.write_le(&mut writer).unwrap();
        println!("{:?}", writer.get_ref());
    }
}
fn main() {
    let data = fs::read("./data/ios").unwrap();
    let mut reader = Cursor::new(&data);
    let mut macho: MachHeader = reader.read_ne().unwrap();
    // macho.cpu_type = CpuType::ARM;

    let mut writer = Cursor::new(vec![]);
    macho.write_le(&mut writer).unwrap();
    let mut file = File::create("./data/ios2").unwrap();
    writer.set_position(0);
    std::io::copy(&mut writer, &mut file).unwrap();

    let data = fs::read("./data/ios2").unwrap();
    let mut reader = Cursor::new(&data);
    let macho = MachHeader::read_ne(&mut reader).unwrap();
    println!("2 {:?}", macho);
    // println!("{}",CPU_TYPE_X86_64);
    // println!("length {:?}", data.len());
}
