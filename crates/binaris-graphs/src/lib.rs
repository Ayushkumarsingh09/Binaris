use binaris_core::{
    ExportEntry, FunctionAnalysis, GraphEdge, GraphNode, GraphPayload, ImportEntry,
};
use serde_json::json;

pub fn build_call_graph(functions: &[FunctionAnalysis]) -> GraphPayload {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for f in functions {
        nodes.push(GraphNode {
            id: format!("fn_{:x}", f.address),
            label: f.suggested_name.clone().unwrap_or_else(|| f.name.clone()),
            kind: "function".into(),
            address: Some(f.address),
            meta: json!({
                "complexity": f.complexity,
                "tags": f.tags,
                "confidence": f.confidence,
            }),
        });
        for target in &f.xrefs_from {
            edges.push(GraphEdge {
                id: uuid::Uuid::now_v7().to_string(),
                source: format!("fn_{:x}", f.address),
                target: format!("fn_{target:x}"),
                kind: "calls".into(),
                label: Some("call".into()),
            });
        }
    }

    // Connect sequential discovered functions as fallback topology when xrefs empty
    if edges.is_empty() && functions.len() > 1 {
        for w in functions.windows(2) {
            edges.push(GraphEdge {
                id: uuid::Uuid::now_v7().to_string(),
                source: format!("fn_{:x}", w[0].address),
                target: format!("fn_{:x}", w[1].address),
                kind: "likely_flow".into(),
                label: Some("next".into()),
            });
        }
    }

    GraphPayload { nodes, edges }
}

pub fn build_cfg_summary(functions: &[FunctionAnalysis]) -> GraphPayload {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for f in functions.iter().take(32) {
        let entry = format!("bb_{:x}_entry", f.address);
        let exit = format!("bb_{:x}_exit", f.address);
        nodes.push(GraphNode {
            id: entry.clone(),
            label: format!("{} entry", f.name),
            kind: "basic_block".into(),
            address: Some(f.address),
            meta: json!({}),
        });
        nodes.push(GraphNode {
            id: exit.clone(),
            label: format!("{} exit", f.name),
            kind: "basic_block".into(),
            address: Some(f.address + f.size),
            meta: json!({}),
        });
        edges.push(GraphEdge {
            id: uuid::Uuid::now_v7().to_string(),
            source: entry,
            target: exit,
            kind: "fallthrough".into(),
            label: None,
        });
    }
    GraphPayload { nodes, edges }
}

pub fn build_import_graph(imports: &[ImportEntry], exports: &[ExportEntry]) -> GraphPayload {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    nodes.push(GraphNode {
        id: "binary".into(),
        label: "binary".into(),
        kind: "binary".into(),
        address: None,
        meta: json!({}),
    });

    let mut modules: Vec<String> = imports.iter().map(|i| i.module.clone()).collect();
    modules.sort();
    modules.dedup();
    for module in modules {
        let id = format!("mod_{module}");
        nodes.push(GraphNode {
            id: id.clone(),
            label: module.clone(),
            kind: "module".into(),
            address: None,
            meta: json!({}),
        });
        edges.push(GraphEdge {
            id: uuid::Uuid::now_v7().to_string(),
            source: "binary".into(),
            target: id.clone(),
            kind: "imports_module".into(),
            label: None,
        });
        for imp in imports.iter().filter(|i| i.module == module).take(40) {
            let sid = format!("imp_{module}_{}", imp.symbol);
            nodes.push(GraphNode {
                id: sid.clone(),
                label: imp.symbol.clone(),
                kind: "import".into(),
                address: imp.address,
                meta: json!({ "risk": imp.risk, "tags": imp.tags }),
            });
            edges.push(GraphEdge {
                id: uuid::Uuid::now_v7().to_string(),
                source: id.clone(),
                target: sid,
                kind: "provides".into(),
                label: None,
            });
        }
    }

    for e in exports.iter().take(64) {
        let id = format!("exp_{}", e.symbol);
        nodes.push(GraphNode {
            id: id.clone(),
            label: e.symbol.clone(),
            kind: "export".into(),
            address: Some(e.address),
            meta: json!({}),
        });
        edges.push(GraphEdge {
            id: uuid::Uuid::now_v7().to_string(),
            source: "binary".into(),
            target: id,
            kind: "exports".into(),
            label: None,
        });
    }

    GraphPayload { nodes, edges }
}

pub fn build_dfg(functions: &[FunctionAnalysis]) -> GraphPayload {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for f in functions.iter().take(48) {
        let def = format!("def_{:x}", f.address);
        let use_n = format!("use_{:x}", f.address);
        nodes.push(GraphNode {
            id: def.clone(),
            label: format!("{} defs", f.suggested_name.as_deref().unwrap_or(&f.name)),
            kind: "def".into(),
            address: Some(f.address),
            meta: json!({ "complexity": f.complexity }),
        });
        nodes.push(GraphNode {
            id: use_n.clone(),
            label: format!("{} uses", f.name),
            kind: "use".into(),
            address: Some(f.address),
            meta: json!({}),
        });
        edges.push(GraphEdge {
            id: uuid::Uuid::now_v7().to_string(),
            source: def,
            target: use_n,
            kind: "dataflow".into(),
            label: Some("ssa".into()),
        });
        for x in &f.xrefs_from {
            edges.push(GraphEdge {
                id: uuid::Uuid::now_v7().to_string(),
                source: format!("use_{:x}", f.address),
                target: format!("def_{x:x}"),
                kind: "flows_to".into(),
                label: None,
            });
        }
    }
    GraphPayload { nodes, edges }
}

pub fn build_memory_graph(
    functions: &[FunctionAnalysis],
    sections: &[binaris_core::SectionInfo],
) -> GraphPayload {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for s in sections {
        nodes.push(GraphNode {
            id: format!("sec_{}", s.name),
            label: format!("{} ent={:.2}", s.name, s.entropy),
            kind: "section".into(),
            address: Some(s.virtual_address),
            meta: json!({ "perms": s.permissions, "size": s.raw_size }),
        });
    }
    for f in functions.iter().take(32) {
        let id = format!("fn_{:x}", f.address);
        nodes.push(GraphNode {
            id: id.clone(),
            label: f.suggested_name.clone().unwrap_or_else(|| f.name.clone()),
            kind: "function".into(),
            address: Some(f.address),
            meta: json!({}),
        });
        if let Some(sec) = sections.iter().find(|s| {
            f.address >= s.virtual_address && f.address < s.virtual_address + s.virtual_size.max(1)
        }) {
            edges.push(GraphEdge {
                id: uuid::Uuid::now_v7().to_string(),
                source: format!("sec_{}", sec.name),
                target: id,
                kind: "contains".into(),
                label: None,
            });
        }
    }
    GraphPayload { nodes, edges }
}
