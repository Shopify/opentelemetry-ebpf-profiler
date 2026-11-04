// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Translates object file (e.g. ELF) symbols into a range symbfile.

use super::{Error, RangeExtractor, RangeVisitor, Result, Stats};
use crate::{demangle, objfile, symbfile};

/// Extracts ranges from object file symbols.
///
/// See [`objfile::Reader::function_symbols`] for the symbols that are included.
pub struct Extractor<'obj> {
    obj: &'obj objfile::Reader<'obj>,
    source: objfile::SymbolSource,
}

impl<'obj> Extractor<'obj> {
    /// Create a new object file symbol extractor.
    pub fn new(obj: &'obj objfile::Reader<'obj>, source: objfile::SymbolSource) -> Self {
        Self { obj, source }
    }
}

impl<'obj> RangeExtractor for Extractor<'obj> {
    fn extract(&self, visitor: RangeVisitor<'_>) -> Result<Option<Stats>> {
        for sym in self.obj.function_symbols(self.source) {
            let rng = obj_symbol_to_range(&sym);
            visitor(rng).map_err(Error::Obj)?;
        }

        Ok(None)
    }
}

/// Translate an object file symbol to a range.
fn obj_symbol_to_range(sym: &objfile::Symbol<'_>) -> symbfile::Range {
    symbfile::Range {
        elf_va: sym.virt_addr,
        length: sym.length as u32,
        func: demangle::demangle(sym.name).into_owned(),
        file: None,
        call_file: None,
        call_line: None,
        depth: 0,
        line_table: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::testdata;
    use objfile::SymbolSource;

    fn ranges(file: &str, source: SymbolSource) -> Vec<(u64, u32, String)> {
        let obj = objfile::File::load(&testdata(file)).unwrap();
        let obj = obj.parse().unwrap();
        let mut ranges = vec![];
        Extractor::new(&obj, source)
            .extract(&mut |rng| {
                ranges.push((rng.elf_va, rng.length, rng.func));
                Ok(())
            })
            .unwrap();
        ranges
    }

    #[test]
    fn debug_symbols_cover_incomplete_asm_symbols() {
        let expected = [
            // Sized functions first, in symbol table order.
            (0x324, 12, "outer_func"),
            (0x300, 8, "sized_func"),
            // Then the rest of the code, by address.
            (0x308, 12, "sizeless_func"),
            (0x314, 8, "untyped_label"),
            (0x31c, 8, "sized_label"),
            (0x330, 16, "last_sizeless_func"),
        ]
        .map(|(va, len, func)| (va, len, func.to_string()));

        // `.debug` has the same symbols, but no code bytes.
        for file in ["asm-symbols", "asm-symbols.debug"] {
            assert_eq!(ranges(file, SymbolSource::Debug), expected, "{file}");
        }
    }

    #[test]
    fn dynamic_symbols_need_a_size() {
        assert_eq!(
            ranges("asm-symbols", SymbolSource::Dynamic),
            [
                (0x324, 12, "outer_func".into()),
                (0x300, 8, "sized_func".into())
            ],
        );
    }
}
