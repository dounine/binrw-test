use binrw::helpers::until_eof;
use binrw::{args, binrw, BinRead, BinReaderExt, BinResult, BinWrite, Endian, NullString};
use std::any::Any;
use std::ffi::{c_char, CStr};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, SeekFrom};
use std::mem::size_of;
use std::ops::Neg;
#[binrw]
// #[brw(is_big = big_endian,import{big_endian: bool})]
#[derive(Debug, PartialEq, Eq)]
enum CpuType {
    #[brw(magic = 7_u32)]
    X86,
    #[brw(magic = 16777223_u32)]
    X86_64,
    #[brw(magic = 12_u32)]
    Arm,
    #[brw(magic = 16777228_u32)]
    Arm64,
    #[brw(magic = 33554444_u32)]
    Arm64_32,
    Unknown(i32),
}

#[binrw]
#[derive(Debug, PartialEq, Eq)]
enum CpuSubtype {
    #[brw(magic(6_u32))]
    ArmV6,
    #[brw(magic(9_u32))]
    ArmV7,
    #[brw(magic(11_u32))]
    ArmV7S,
    #[brw(magic(12_u32))]
    ArmV7K,
    #[brw(magic(13_u32))]
    ArmV8,
    #[brw(magic(0_u32))]
    Arm64All,
    #[brw(magic(1_u32))]
    Arm64V8,
    #[brw(magic(2_u32))]
    Arm64E,
    Unknown(u32),
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
#[brw(is_big=big_endian,import(is_u64:bool,big_endian:bool))]
#[derive(Debug)]
struct Section<T: for<'a> BinRead<Args<'a> = ()> + for<'a> BinWrite<Args<'a> = ()>> {
    #[br(parse_with = parse_cstring, args(16,))]
    #[bw(write_with = writer_cstring,args(16,))]
    section_name: String,
    #[br(parse_with = parse_cstring, args(16,))]
    #[bw(write_with = writer_cstring,args(16,))]
    segment_name: String,
    addr: T,
    size: T,
    offset: u32,
    align: u32,
    rel_offset: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    #[br(if(is_u64))]
    reserved3: Option<u32>,
}
#[binrw]
#[brw(is_big=big_endian,import(big_endian:bool))]
#[derive(Debug)]
struct BuildToolVersion {
    tool: u32,
    version: u32,
}
#[binrw]
#[brw(is_big=big_endian,import(big_endian:bool))]
#[derive(Debug)]
enum LoadCommand {
    #[brw(magic = 0x00000001_u32)]
    Segment {
        cmd_size: u32,
        #[br(map = |v:[u8;16]| map_cstring(&v))]
        #[bw(map = |v:&String| map_cstring_bytes(v))]
        segment_name: String,
        vm_addr: u32,
        vm_size: u32,
        file_offset: u32,
        file_size: u32,
        max_prot: i32,
        init_prot: i32,
        #[br(temp)]
        #[bw(calc = sections.len() as u32)]
        nsects: u32,
        flags: u32,
        #[br(count = nsects)]
        #[br(args{inner:(false,big_endian,)})]
        sections: Vec<Section<u32>>,
    },
    #[brw(magic = 0x00000019_u32)]
    Segment64 {
        cmd_size: u32,
        #[br(parse_with = parse_cstring, args(16,))]
        #[bw(write_with = writer_cstring,args(16,))]
        segment_name: String,
        vm_addr: u64,
        vm_size: u64,
        file_offset: u64,
        file_size: u64,
        max_prot: i32,
        init_prot: i32,
        #[br(temp)]
        #[bw(calc = sections.len() as u32)]
        nsects: u32,
        flags: u32,
        #[br(count = nsects)]
        #[br(args{inner:(true,big_endian,)})]
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
    #[brw(magic = 0x80000022_u32)]
    DyldInfoOnly {
        cmd_size: u32,
        rebase_info_offset: u32,
        rebase_info_size: u32,
        bind_info_offset: u32,
        bind_info_size: u32,
        weak_binding_info_offset: u32,
        weak_binding_info_size: u32,
        lazy_binding_info_offset: u32,
        lazy_binding_info_size: u32,
        export_info_offset: u32,
        export_info_size: u32,
    },
    #[brw(magic = 0x00000026_u32)]
    FunctionStarts {
        cmd_size: u32,
        file_offset: u32,
        file_size: u32,
    },
    #[brw(magic = 0x00000029_u32)]
    DataInCode {
        cmd_size: u32,
        file_offset: u32,
        file_size: u32,
    },
    #[brw(magic = 0x00000002_u32)]
    SymTab {
        cmd_size: u32,
        symbol_table_offset: u32,
        number_of_symbols: u32,
        string_table_offset: u32,
        string_table_size: u32,
    },
    #[brw(magic = 0x8000001c_u32)]
    RPath {
        cmd_size: u32,
        str_offset: u32,
        #[br(parse_with = parse_cstring, args((cmd_size-str_offset) as usize,))]
        #[bw(write_with = writer_cstring,args((cmd_size-str_offset) as usize,))]
        path: String,
    },
    #[brw(magic = 0x0000000d_u32)]
    IdDylib {
        cmd_size: u32,
        str_offset: u32,
        time_stamp: u32,
        current_version: u32,
        compatibility_version: u32,
        #[br(parse_with = parse_cstring, args((cmd_size-str_offset) as usize,))]
        #[bw(write_with = writer_cstring,args((cmd_size-str_offset) as usize,))]
        path: String,
    },
    #[brw(magic = 0x0000000c_u32)]
    LoadDylib {
        cmd_size: u32,
        str_offset: u32,
        time_stamp: u32,
        current_version: u32,
        compatibility_version: u32,
        #[br(parse_with = parse_cstring, args((cmd_size-str_offset) as usize,))]
        #[bw(write_with = writer_cstring,args((cmd_size-str_offset) as usize,))]
        name: String,
    },
    #[brw(magic = 0x00000025_u32)]
    VersionMinIphoneos {
        cmd_size: u32,
        version: u32,
        reserved: u32,
    },
    #[brw(magic = 0x00000032_u32)]
    BundleVersion {
        cmd_size: u32,
        platform: u32,
        minimum_os_version: u32,
        bundle_sdk_version: u32,
        #[br(temp)]
        #[bw(calc = build_tool_versions.len() as u32)]
        number_of_tools_entries: u32,
        #[br(count = number_of_tools_entries,args{inner:(big_endian,)})]
        build_tool_versions: Vec<BuildToolVersion>,
    },
    #[brw(magic = 0x0000000e_u32)]
    LoadDyLinker {
        cmd_size: u32,
        str_offset: u32,
        #[br(parse_with = parse_cstring, args((cmd_size-str_offset) as usize,))]
        #[bw(write_with = writer_cstring,args((cmd_size-str_offset) as usize,))]
        name: String,
    },
    #[brw(magic = 0x0000001b_u32)]
    Uuid {
        cmd_size: u32,
        #[br(map = |v:[u8;16]| uuid::Uuid::from_bytes(v))]
        #[bw(map = |v:&uuid::Uuid| v.as_bytes().to_vec())]
        uuid: uuid::Uuid,
    },
    #[brw(magic = 0x0000002a_u32)]
    SourceVersion { cmd_size: u32, version: u64 },
    #[brw(magic = 0x0000000b_u32)]
    DySymTab {
        cmd_size: u32,
        loc_symbol_index: u32,
        loc_symbol_number: u32,
        defined_ext_symbol_index: u32,
        defined_ext_symbol_number: u32,
        undef_ext_symbol_index: u32,
        undef_ext_symbol_number: u32,
        toc_offset: u32,
        toc_entries: u32,
        module_table_offset: u32,
        module_table_entries: u32,
        ext_ref_table_offset: u32,
        ext_ref_table_entries: u32,
        ind_sym_table_offset: u32,
        ind_sym_table_entries: u32,
        ext_reloc_table_offset: u32,
        ext_reloc_table_entries: u32,
        loc_reloc_table_offset: u32,
        loc_reloc_table_entries: u32,
    },
    #[brw(magic = 0x80000028_u32)]
    Main {
        cmd_size: u32,
        entry_offset: u64,
        stacks_size: u64,
    },
    #[brw(magic = 0x0000001d_u32)]
    CodeSignature {
        cmd_size: u32,
        file_offset: u32,
        file_size: u32,
    },
    // Unknown {
    //     //todo 应该匹配所有Command，不应该进来这里
    //     cmd: CmdType,
    //     #[bw(calc = (data.len() + 8) as u32)]
    //     cmd_size: u32,
    //     #[br(count = cmd_size - 8)]
    //     data: Vec<u8>,
    // },
}

#[binrw]
#[br(import{ cmd_size:u32 })]
#[derive(Debug, Default)]
struct CommandInfo {
    #[br(count = cmd_size )]
    data: Vec<u8>,
}
#[binrw::parser(reader)]
fn parse_cstring(size: usize) -> BinResult<String> {
    let mut buffer = vec![0u8; size];
    reader.read_exact(&mut buffer)?;
    let c_char = buffer.as_ptr() as *const c_char;
    let c_str = unsafe { CStr::from_ptr(c_char) };
    Ok(c_str.to_string_lossy().to_string())
}
#[binrw::writer(writer)]
fn writer_cstring(data: &String, size: usize) -> BinResult<()> {
    let mut data = data.as_bytes().to_vec();
    data.resize(size, 0u8);
    data.write(writer)?;
    Ok(())
}
fn map_cstring(data: &[u8]) -> String {
    let c_char = data.as_ptr() as *const c_char;
    let c_str = unsafe { CStr::from_ptr(c_char) };
    c_str.to_string_lossy().to_string()
}
fn map_cstring_bytes(str: &String) -> Vec<u8> {
    let mut data = str.as_bytes().to_vec();
    data.resize(16, 0u8);
    data
}
#[binrw]
#[brw(is_big=big_endian,import(big_endian:bool))]
#[derive(Debug)]
pub struct MachHeader {
    magic: MachType, // mach magic 标识符，用来确定其属于 64位 还是 32位
    #[br(seek_before = SeekFrom::Current(-4),map = |magic:MachType| matches!(magic,MachType::MachoMagic64|MachType::MachoCiGam64))]
    #[bw(ignore)]
    bit_64: bool, //是否是64位的二进制文件
    // #[brw( args { big_endian: big_endian.clone() } )]
    cpu_type: CpuType,       //CPU 类型标识符，同通用二进制格式中的定义
    cpu_subtype: CpuSubtype, //CPU 子类型标识符，同通用二级制格式中的定义
    file_type: FileType,     //文件类型，主要用来区分可执行文件、动态库、静态库等
    count_of_cmds: u32,      //加载器中加载命令(Load commands)的数量
    size_of_cmds: u32,       //加载器中加载命令的总字节大小
    flags: u32,              // 标志位，主要用来表示是否是64位的二进制文件，是否是可执行文件等
    #[brw(if(bit_64.clone()))]
    reserved: Option<u32>, // 64 位的保留字段

    #[br(count = count_of_cmds)]
    #[br(args{inner:(big_endian,)})]
    commands: Vec<LoadCommand>,
}
#[binrw]
#[derive(Debug)]
pub struct FatHeader {
    magic: MachType, // mach magic 标识符，用来确定其属于 64位 还是 32位
    #[br(seek_before = SeekFrom::Current(-4),map = |magic:MachType| matches!(magic,MachType::FatCiGam|MachType::MachoCiGam|MachType::MachoCiGam64))]
    #[bw(ignore)]
    big_endian: bool,
    #[br(temp)]
    #[bw(calc = archs.len() as u32)]
    number_of_architecture: u32,
    #[br(count = number_of_architecture)]
    #[br(args{inner:(big_endian,)})]
    archs: Vec<FatArch>,
}
#[binrw]
#[brw(import(big_endian:bool))]
#[derive(Debug)]
pub struct FatArch {
    cpu_type: CpuType,
    cpu_subtype: CpuSubtype,
    offset: u32,
    size: u32,
    align: u32,
    #[br(align_before = offset)]
    #[bw(align_before = *offset)]
    #[br(is_big=big_endian)]
    mach: MachHeader,
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
    use crate::{FatHeader, MachHeader, MachType};
    use binrw::{binrw, BinReaderExt, BinResult, BinWrite, Endian};
    use std::fs;
    use std::fs::File;
    use std::io::{Cursor, Read, SeekFrom};
    // #[binrw::parser]
    // fn bool_reader(reader: &mut dyn Read, is_big: bool) -> BinResult<bool> {
    //
    // }

    #[test]
    fn test_read_ios_dylib() {
        let data = fs::read("./data/ios.dylib").unwrap();
        println!("before length:{}", data.len());
        let mut reader = Cursor::new(&data);
        let magic: MachType = reader.read_le().unwrap();
        let endian = if magic == MachType::FatCiGam || magic == MachType::MachoCiGam {
            Endian::Big
        } else {
            Endian::Little
        };
        reader.set_position(0);
        let fat_header: FatHeader = reader.read_type(endian).unwrap();
        println!("magic : {:?}", fat_header);

        let mut writer = Cursor::new(vec![]);
        if endian == Endian::Big {
            fat_header.write_be(&mut writer).unwrap();
        } else {
            fat_header.write_le(&mut writer).unwrap();
        }
        let mut file = File::create("./data/ios2.dylib").unwrap();
        writer.set_position(0);
        std::io::copy(&mut writer, &mut file).unwrap();
        println!("after length: {:#?}", writer.get_ref().len());
    }

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
    // macho.cpu_type = CpuType::X86_64;

    println!("before length:{}", data.len());
    let mut writer = Cursor::new(vec![]);
    macho.write_le(&mut writer).unwrap();
    let mut file = File::create("./data/ios2").unwrap();
    writer.set_position(0);
    std::io::copy(&mut writer, &mut file).unwrap();
    println!("after length:{}", writer.get_ref().len());
    //
    // let data = fs::read("./data/ios2").unwrap();
    // let mut reader = Cursor::new(&data);
    // let macho = MachHeader::read_ne(&mut reader).unwrap();
    println!("2 {:?}", macho);
    // println!("{}",CPU_TYPE_X86_64);
    // println!("length {:?}", data.len());
}
