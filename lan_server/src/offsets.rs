use std::mem;

pub const WINDOWS_24H2_BUILD: u32 = 26_100;
pub const WINDOWS_25H2_BUILD: u32 = 26_200;

#[derive(Clone, Copy, Debug)]
pub struct Offsets {
    pub list_entry_flink: u64,
    pub list_entry_blink: u64,
    pub kprocess_directory_table_base: u64,
    pub kprocess_user_directory_table_base: u64,
    pub eprocess_unique_process_id: u64,
    pub eprocess_active_process_links: u64,
    pub eprocess_peb: u64,
    pub eprocess_wow64_process: u64,
    pub eprocess_image_file_name: u64,
    pub peb_image_base_address: u64,
    pub peb_ldr: u64,
    pub peb_ldr_length: u64,
    pub peb_ldr_initialized: u64,
    pub peb_ldr_in_load_order_module_list: u64,
    pub peb_ldr_in_memory_order_module_list: u64,
    pub peb_ldr_in_initialization_order_module_list: u64,
    pub ldr_entry_in_load_order_links: u64,
    pub ldr_entry_in_memory_order_links: u64,
    pub ldr_entry_in_initialization_order_links: u64,
    pub ldr_entry_dll_base: u64,
    pub ldr_entry_size_of_image: u64,
    pub ldr_entry_full_dll_name: u64,
    pub ldr_entry_base_dll_name: u64,
    pub unicode_string_length: u64,
    pub unicode_string_maximum_length: u64,
    pub unicode_string_buffer: u64,
    pub mmpfn_size: u64,
    pub mmpfn_pte_address: u64,
    pub mmpfn_page_location: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct OffsetProfile {
    pub build: u32,
    pub release: &'static str,
    pub offsets: Offsets,
}

pub const OFFSETS_24H2: Offsets = Offsets {
    list_entry_flink: 0x0,
    list_entry_blink: 0x8,
    kprocess_directory_table_base: 0x28,
    kprocess_user_directory_table_base: 0x158,
    eprocess_unique_process_id: 0x1d0,
    eprocess_active_process_links: 0x1d8,
    eprocess_peb: 0x2e0,
    eprocess_wow64_process: 0x310,
    eprocess_image_file_name: 0x338,
    peb_image_base_address: 0x10,
    peb_ldr: 0x18,
    peb_ldr_length: 0x0,
    peb_ldr_initialized: 0x4,
    peb_ldr_in_load_order_module_list: 0x10,
    peb_ldr_in_memory_order_module_list: 0x20,
    peb_ldr_in_initialization_order_module_list: 0x30,
    ldr_entry_in_load_order_links: 0x0,
    ldr_entry_in_memory_order_links: 0x10,
    ldr_entry_in_initialization_order_links: 0x20,
    ldr_entry_dll_base: 0x30,
    ldr_entry_size_of_image: 0x40,
    ldr_entry_full_dll_name: 0x48,
    ldr_entry_base_dll_name: 0x58,
    unicode_string_length: 0x0,
    unicode_string_maximum_length: 0x2,
    unicode_string_buffer: 0x8,
    mmpfn_size: 0x30,
    mmpfn_pte_address: 0x8,
    mmpfn_page_location: 0x22,
};

pub const OFFSETS_25H2: Offsets = Offsets {
    list_entry_flink: 0x0,
    list_entry_blink: 0x8,
    kprocess_directory_table_base: 0x28,
    kprocess_user_directory_table_base: 0x158,
    eprocess_unique_process_id: 0x1d0,
    eprocess_active_process_links: 0x1d8,
    eprocess_peb: 0x2e0,
    eprocess_wow64_process: 0x310,
    eprocess_image_file_name: 0x338,
    peb_image_base_address: 0x10,
    peb_ldr: 0x18,
    peb_ldr_length: 0x0,
    peb_ldr_initialized: 0x4,
    peb_ldr_in_load_order_module_list: 0x10,
    peb_ldr_in_memory_order_module_list: 0x20,
    peb_ldr_in_initialization_order_module_list: 0x30,
    ldr_entry_in_load_order_links: 0x0,
    ldr_entry_in_memory_order_links: 0x10,
    ldr_entry_in_initialization_order_links: 0x20,
    ldr_entry_dll_base: 0x30,
    ldr_entry_size_of_image: 0x40,
    ldr_entry_full_dll_name: 0x48,
    ldr_entry_base_dll_name: 0x58,
    unicode_string_length: 0x0,
    unicode_string_maximum_length: 0x2,
    unicode_string_buffer: 0x8,
    mmpfn_size: 0x30,
    mmpfn_pte_address: 0x8,
    mmpfn_page_location: 0x22,
};

pub const PROFILE_26100_X64: OffsetProfile = OffsetProfile {
    build: WINDOWS_24H2_BUILD,
    release: "24H2",
    offsets: OFFSETS_24H2,
};

pub const PROFILE_26200_X64: OffsetProfile = OffsetProfile {
    build: WINDOWS_25H2_BUILD,
    release: "25H2",
    offsets: OFFSETS_25H2,
};

#[repr(C)]
struct RtlOsVersionInfoW {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform_id: u32,
    service_pack: [u16; 128],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version: *mut RtlOsVersionInfoW) -> i32;
}

pub fn require_supported_build() -> Result<OffsetProfile, String> {
    let mut version: RtlOsVersionInfoW = unsafe { mem::zeroed() };
    version.size = mem::size_of::<RtlOsVersionInfoW>() as u32;
    let status = unsafe { RtlGetVersion(&mut version) };
    if status < 0 {
        return Err(format!("RtlGetVersion failed with NTSTATUS 0x{status:08X}"));
    }
    if version.major != 10 {
        return Err(format!(
            "unsupported Windows version {}.{}.{}; expected Windows 11 x64 build {} or {}",
            version.major, version.minor, version.build, WINDOWS_24H2_BUILD, WINDOWS_25H2_BUILD,
        ));
    }
    match version.build {
        WINDOWS_24H2_BUILD => Ok(PROFILE_26100_X64),
        WINDOWS_25H2_BUILD => Ok(PROFILE_26200_X64),
        build => Err(format!(
            "unsupported Windows build {build}; supported x64 builds are {} (24H2) and {} (25H2)",
            WINDOWS_24H2_BUILD, WINDOWS_25H2_BUILD
        )),
    }
}
