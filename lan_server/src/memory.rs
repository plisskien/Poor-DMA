use std::{cell::RefCell, collections::HashMap, rc::Rc};

use crate::driver::Ksld;

pub const PFN_MASK: u64 = 0x0000_ffff_ffff_f000;
const LARGE_1G_MASK: u64 = 0x0000_ffff_c000_0000;
const LARGE_2M_MASK: u64 = 0x0000_ffff_ffe0_0000;
const RESERVED_PHYSICAL_BITS: u64 = 0x000f_0000_0000_0000;
const PAGE_SIZE: usize = 0x1000;
type PageTablePages = HashMap<u64, Box<[u8; PAGE_SIZE]>>;

const LEAF_TABLE_TTL: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Clone)]
pub struct TranslationCache {
    pages: Rc<RefCell<PageTablePages>>,

    leaves: Rc<RefCell<PageTablePages>>,
    leaves_filled: Rc<std::cell::Cell<std::time::Instant>>,
}

impl Default for TranslationCache {
    fn default() -> Self {
        Self {
            pages: Rc::default(),
            leaves: Rc::default(),
            leaves_filled: Rc::new(std::cell::Cell::new(std::time::Instant::now())),
        }
    }
}

impl TranslationCache {
    pub fn clear(&self) {
        self.pages.borrow_mut().clear();
        self.clear_leaves();
    }

    fn clear_leaves(&self) {
        self.leaves.borrow_mut().clear();
        self.leaves_filled.set(std::time::Instant::now());
    }

    fn leaves(&self) -> &RefCell<PageTablePages> {
        if self.leaves_filled.get().elapsed() >= LEAF_TABLE_TTL {
            self.clear_leaves();
        }
        &self.leaves
    }
}

pub struct VirtualMemory<'a> {
    driver: &'a Ksld,
    dtb: u64,
    trace: bool,
    upper_page_tables: TranslationCache,
}

impl<'a> VirtualMemory<'a> {
    pub fn new(driver: &'a Ksld, dtb: u64) -> Result<Self, String> {
        Self::new_cached(driver, dtb, TranslationCache::default())
    }

    pub fn new_cached(
        driver: &'a Ksld,
        dtb: u64,
        upper_page_tables: TranslationCache,
    ) -> Result<Self, String> {
        let dtb = dtb & PFN_MASK;
        if dtb == 0 {
            return Err("page-table base is zero".to_string());
        }
        Ok(Self {
            driver,
            dtb,
            trace: false,
            upper_page_tables,
        })
    }

    pub fn traced(mut self, enabled: bool) -> Self {
        self.trace = enabled;
        self
    }

    pub fn translate(&self, va: u64) -> Result<u64, String> {
        if !is_canonical_x64(va) {
            return Err(format!("VA 0x{va:X} is not canonical for 4-level paging"));
        }

        let mut table = self.dtb;
        for &(shift, large_mask) in &[(39u32, 0u64), (30, LARGE_1G_MASK), (21, LARGE_2M_MASK)] {
            let index = (va >> shift) & 0x1ff;
            let entry = self.read_page_table_entry(&self.upper_page_tables.pages, table, index)?;
            if entry & 1 == 0 {
                return Err(format!(
                    "non-present page-table entry at level shift {shift}"
                ));
            }
            if entry & RESERVED_PHYSICAL_BITS != 0 {
                return Err(format!(
                    "page-table entry at level shift {shift} has reserved physical bits"
                ));
            }

            if large_mask != 0 && entry & 0x80 != 0 {
                let page_mask = (1u64 << shift) - 1;
                return Ok((entry & large_mask) | (va & page_mask));
            }
            table = entry & PFN_MASK;
            if table == 0 {
                return Err(format!("null next-level table at level shift {shift}"));
            }
        }

        let entry = self.read_page_table_entry(
            self.upper_page_tables.leaves(),
            table,
            (va >> 12) & 0x1ff,
        )?;
        if entry & 1 != 0 {
            if entry & RESERVED_PHYSICAL_BITS != 0 {
                return Err("leaf PTE has reserved physical bits".to_string());
            }
            return Ok((entry & PFN_MASK) | (va & 0xfff));
        }

        let transition = entry & (1 << 11) != 0;
        let prototype = entry & (1 << 10) != 0;
        if transition && !prototype {
            return Ok((entry & PFN_MASK) | (va & 0xfff));
        }

        Err("leaf PTE is not resident (prototype/pagefile/compressed/unmapped)".to_string())
    }

    pub fn read(&self, va: u64, size: usize) -> Result<Vec<u8>, String> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let last = u64::try_from(size - 1)
            .map_err(|_| "requested read size does not fit in u64".to_string())?;
        va.checked_add(last)
            .ok_or_else(|| "virtual-address range overflow".to_string())?;

        let mut segments: Vec<(u64, u64, usize)> = Vec::new();
        let mut offset = 0usize;
        while offset < size {
            let current_va = va + offset as u64;
            let page_offset = (current_va & 0xfff) as usize;
            let chunk = (size - offset).min(PAGE_SIZE - page_offset);
            let pa = self
                .translate(current_va)
                .map_err(|error| format!("translation failed for VA 0x{current_va:X}: {error}"))?;

            if let Some((_, last_pa, last_size)) = segments.last_mut()
                && last_pa.checked_add(*last_size as u64) == Some(pa)
            {
                *last_size += chunk;
            } else {
                segments.push((current_va, pa, chunk));
            }
            offset += chunk;
        }

        let mut output = Vec::with_capacity(size);
        for (segment_va, pa, segment_size) in segments {
            if self.trace {
                println!("[+] VA 0x{segment_va:X} -> PA 0x{pa:X} ({segment_size} bytes)");
            }
            let data = self
                .driver
                .phys_read(pa, segment_size)
                .map_err(|error| format!("physical read failed at PA 0x{pa:X}: {error}"))?;
            output.extend_from_slice(&data);
        }
        Ok(output)
    }

    pub fn read_zero_padded(&self, va: u64, size: usize) -> Result<Vec<u8>, String> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let last = u64::try_from(size - 1)
            .map_err(|_| "requested read size does not fit in u64".to_string())?;
        va.checked_add(last)
            .ok_or_else(|| "virtual-address range overflow".to_string())?;

        let mut segments: Vec<(usize, u64, usize)> = Vec::new();
        let mut offset = 0usize;
        while offset < size {
            let current_va = va + offset as u64;
            let page_offset = (current_va & 0xfff) as usize;
            let chunk = (size - offset).min(PAGE_SIZE - page_offset);
            if let Ok(pa) = self.translate(current_va) {
                if let Some((last_offset, last_pa, last_size)) = segments.last_mut()
                    && last_offset.checked_add(*last_size) == Some(offset)
                    && last_pa.checked_add(*last_size as u64) == Some(pa)
                {
                    *last_size += chunk;
                } else {
                    segments.push((offset, pa, chunk));
                }
            }
            offset += chunk;
        }

        let mut output = vec![0u8; size];
        for (output_offset, pa, segment_size) in segments {
            if let Ok(data) = self.driver.phys_read(pa, segment_size) {
                output[output_offset..output_offset + segment_size].copy_from_slice(&data);
                continue;
            }

            let mut segment_offset = 0usize;
            while segment_offset < segment_size {
                let current_pa = pa + segment_offset as u64;
                let page_offset = (current_pa & 0xfff) as usize;
                let chunk = (segment_size - segment_offset).min(PAGE_SIZE - page_offset);
                if let Ok(data) = self.driver.phys_read(current_pa, chunk) {
                    let start = output_offset + segment_offset;
                    output[start..start + chunk].copy_from_slice(&data);
                }
                segment_offset += chunk;
            }
        }
        Ok(output)
    }

    pub fn read_u8(&self, va: u64) -> Result<u8, String> {
        Ok(self.read(va, 1)?[0])
    }

    pub fn read_u64(&self, va: u64) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.read_array(va)?))
    }

    fn read_array<const N: usize>(&self, va: u64) -> Result<[u8; N], String> {
        self.read(va, N)?
            .try_into()
            .map_err(|_| format!("short virtual read at 0x{va:X}"))
    }

    fn read_page_table_entry(
        &self,
        page_tables: &RefCell<PageTablePages>,
        table: u64,
        index: u64,
    ) -> Result<u64, String> {
        let table = table & PFN_MASK;
        if index >= 512 {
            return Err(format!("page-table index {index} exceeds 511"));
        }

        if !page_tables.borrow().contains_key(&table) {
            let page = self
                .driver
                .phys_read(table, PAGE_SIZE)
                .map_err(|error| format!("page-table read failed at PA 0x{table:X}: {error}"))?;
            let page: Box<[u8; PAGE_SIZE]> =
                page.into_boxed_slice()
                    .try_into()
                    .map_err(|page: Box<[u8]>| {
                        format!(
                            "short page-table read at PA 0x{table:X}: received {} bytes",
                            page.len()
                        )
                    })?;
            page_tables.borrow_mut().insert(table, page);
        }

        let offset = index as usize * 8;
        let cache = page_tables.borrow();
        let page = cache
            .get(&table)
            .ok_or_else(|| format!("page-table cache lost PA 0x{table:X}"))?;
        Ok(u64::from_le_bytes(
            page[offset..offset + 8].try_into().unwrap(),
        ))
    }
}

pub fn checked_field(base: u64, offset: u64, field: &str) -> Result<u64, String> {
    base.checked_add(offset)
        .ok_or_else(|| format!("{field} address overflow"))
}

pub fn is_canonical_x64(va: u64) -> bool {
    let upper = va >> 48;
    if va & (1 << 47) == 0 {
        upper == 0
    } else {
        upper == 0xffff
    }
}

pub fn is_kernel_address(va: u64) -> bool {
    is_canonical_x64(va) && va & (1 << 47) != 0
}

pub fn is_user_address(va: u64) -> bool {
    va >= 0x10000 && is_canonical_x64(va) && va & (1 << 47) == 0
}
