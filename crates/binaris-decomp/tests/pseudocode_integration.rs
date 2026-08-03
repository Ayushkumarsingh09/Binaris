use binaris_decomp::pseudocode::from_assembly_preview;

#[test]
fn entry_pseudocode_contains_calls() {
    let asm = "call 0x401000\nmov eax, 1\nret";
    let pc = from_assembly_preview(asm, "entry");
    assert!(pc.contains("call("));
    assert!(pc.contains("return"));
}
