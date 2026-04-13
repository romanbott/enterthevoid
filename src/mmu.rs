use std::collections::HashMap;

/// Standard page size in bytes (4 KB).
pub const PAGE_SIZE: usize = 4096;
/// Total physical memory size for the simulation arena (64 KB).
pub const ARENA_SIZE: usize = 64 * 1024;

/// Represents an entry in the simulated page table.
#[derive(Debug, Clone, Copy)]
pub struct PageTableEntry {
    /// The base physical address frame.
    pub physical_frame: usize,
    /// Indicates if the page is currently mapped and accessible.
    pub valid: bool,
}

/// Simulated Memory Management Unit (MMU) with internal paging.
/// It operates entirely on an isolated arena.
pub struct Mmu {
    /// The simulated physical memory arena.
    arena: Vec<u8>,
    /// The page table mapping logical page numbers to physical frames.
    page_table: HashMap<usize, PageTableEntry>,
}

impl Default for Mmu {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmu {
    /// Creates a new isolated MMU instance with zeroed memory.
    pub fn new() -> Self {
        Self {
            arena: vec![0; ARENA_SIZE],
            page_table: HashMap::new(),
        }
    }

    /// Computes page number from logical address.
    pub fn get_page_num(&self, logical_addr: usize) -> usize {
        return logical_addr / PAGE_SIZE;
    }

    /// Maps a logical page to a physical frame.
    pub fn map_page(&mut self, logical_addr: usize) -> Result<(), &'static str> {
        let page_num = self.get_page_num(logical_addr);
        let physical_frame = (page_num * PAGE_SIZE) % ARENA_SIZE;

        self.page_table.insert(
            page_num,
            PageTableEntry {
                physical_frame,
                valid: true,
            },
        );
        Ok(())
    }

    /// Translates a logical address into a physical address within the arena.
    pub fn translate(&self, logical_addr: usize) -> Result<usize, &'static str> {
        let page_num = logical_addr / PAGE_SIZE;
        let offset = logical_addr % PAGE_SIZE;

        match self.page_table.get(&page_num) {
            Some(entry) if entry.valid => {
                let phys_addr = entry.physical_frame + offset;
                if phys_addr < self.arena.len() {
                    Ok(phys_addr)
                } else {
                    Err("Physical address out of bounds (Arena Overflow)")
                }
            }
            _ => Err("Page Fault: Address not mapped"),
        }
    }

    /// Reads a byte from the given logical address.
    pub fn read(&self, logical_addr: usize) -> Result<u8, &'static str> {
        let phys_addr = self.translate(logical_addr)?;
        Ok(self.arena[phys_addr])
    }

    /// Writes a byte to the given logical address.
    pub fn write(&mut self, logical_addr: usize, value: u8) -> Result<(), &'static str> {
        let phys_addr = self.translate(logical_addr)?;
        self.arena[phys_addr] = value;
        Ok(())
    }
}
