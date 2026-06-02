//! `omc graph` — resolve a package's dependency graph (read-only, into a
//! throwaway temp dir exactly like `omc inspect`) and render a PNG visualizing
//! it with a PURE-RUST renderer (tiny-skia + a tiny built-in bitmap font). No
//! graphviz / `dot` / system tools are invoked, and nothing is written into the
//! user's project: resolution lands in a sandboxed scratch dir, and the only
//! file we write is the requested PNG.
//!
//! Nodes are packages (label: "name version" plus a short capability summary);
//! edges are "depends on" relations derived from each report's
//! `artifact.dependencies` matched to the child report by name. Nodes are
//! risk-colored:
//!   * RED    — dynamic_eval OR fs_write OR proc_spawn (code execution / writes)
//!   * YELLOW — other host capabilities (env_read / fs_read / http_request)
//!   * GREY   — no host access
//!
//! Like inspect, this is informational: blocked packages are recorded (not
//! thrown on) so the whole tree renders.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use omc_registry::{add_package_graph, CapabilityKind, LinkOptions, LinkReport, OmcRegistryError};
use tiny_skia::{Color, Paint, PathBuilder, Pixmap, Rect, Stroke, Transform};

use crate::manifest::{ecosystem_hint, parse_package_specs};
use crate::policy_args::apply_cli_policy_options;

/// Arguments for `omc graph`, mirroring the resolve-relevant subset of `add`
/// plus the PNG output path.
pub(crate) struct GraphCommand {
    pub(crate) npm: bool,
    pub(crate) pypi: bool,
    pub(crate) specs: Vec<String>,
    pub(crate) output: PathBuf,
    pub(crate) allow: Vec<String>,
    pub(crate) allow_flow: Vec<String>,
    pub(crate) allow_all_host: bool,
}

pub(crate) fn run_graph(command: GraphCommand) -> Result<ExitCode, OmcRegistryError> {
    let specs = parse_package_specs(&command.specs, ecosystem_hint(command.npm, command.pypi))?;

    // Resolve into a unique throwaway directory so NOTHING is written to the
    // user's project (matches `omc inspect`'s read-only contract).
    let scratch = ScratchDir::new()?;

    let mut options = LinkOptions::new(scratch.path());
    // Record (don't throw on) blocked packages so a blocked dependency is still
    // graphed rather than aborting the whole render.
    options.record_blocked = true;
    apply_cli_policy_options(
        &mut options,
        &command.allow,
        &command.allow_flow,
        command.allow_all_host,
    )?;

    let mut reports = Vec::new();
    for spec in &specs {
        reports.extend(add_package_graph(spec, &options)?);
    }

    let graph = DependencyGraph::from_reports(&reports);
    let pixmap = render_graph(&graph);
    pixmap
        .save_png(&command.output)
        .map_err(|err| OmcRegistryError::UnsupportedSpec(format!("failed to write PNG: {err}")))?;

    println!(
        "wrote {} ({} nodes, {} edges)",
        command.output.display(),
        graph.nodes.len(),
        graph.edges.len()
    );

    Ok(ExitCode::SUCCESS)
}

/// Risk tier used to color a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Risk {
    /// dynamic_eval OR fs_write OR proc_spawn.
    High,
    /// other host capabilities (env_read / fs_read / http_request).
    Medium,
    /// no host access.
    None,
}

impl Risk {
    fn color(self) -> Color {
        match self {
            Risk::High => Color::from_rgba8(0xE5, 0x39, 0x35, 0xFF), // red
            Risk::Medium => Color::from_rgba8(0xF6, 0xC3, 0x43, 0xFF), // yellow
            Risk::None => Color::from_rgba8(0xBD, 0xBD, 0xBD, 0xFF), // grey
        }
    }
}

/// Classify a report's capabilities into a risk tier.
pub(crate) fn classify_risk(report: &LinkReport) -> Risk {
    let has = |kind: CapabilityKind| {
        report
            .artifact
            .capabilities
            .iter()
            .any(|finding| finding.kind == kind)
    };
    if has(CapabilityKind::DynamicEval)
        || has(CapabilityKind::FsWrite)
        || has(CapabilityKind::ProcSpawn)
    {
        Risk::High
    } else if has(CapabilityKind::EnvRead)
        || has(CapabilityKind::FsRead)
        || has(CapabilityKind::HttpRequest)
    {
        Risk::Medium
    } else {
        Risk::None
    }
}

/// A short, single-line capability summary for a node label.
fn capability_summary(report: &LinkReport) -> String {
    let mut kinds: BTreeSet<&'static str> = BTreeSet::new();
    for finding in &report.artifact.capabilities {
        let tag = match finding.kind {
            CapabilityKind::DynamicEval => "eval",
            CapabilityKind::FsWrite => "fs-write",
            CapabilityKind::ProcSpawn => "proc",
            CapabilityKind::EnvRead => "env",
            CapabilityKind::FsRead => "fs-read",
            CapabilityKind::HttpRequest => "net",
        };
        kinds.insert(tag);
    }
    if kinds.is_empty() {
        "no host access".to_owned()
    } else {
        kinds.into_iter().collect::<Vec<_>>().join(" ")
    }
}

/// A node in the dependency graph.
#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) caps: String,
    pub(crate) risk: Risk,
    /// BFS depth from any root (used for the layered layout).
    pub(crate) depth: usize,
}

impl Node {
    fn header(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// A directed dependency graph built from a set of `LinkReport`s.
#[derive(Debug, Default)]
pub(crate) struct DependencyGraph {
    pub(crate) nodes: Vec<Node>,
    /// (from_index, to_index) "depends on" edges.
    pub(crate) edges: Vec<(usize, usize)>,
}

impl DependencyGraph {
    /// Build a graph from resolved reports. Nodes are keyed by
    /// "ecosystem:name" so a package that appears once becomes one node; edges
    /// connect a package to each of its (production/optional/peer) dependencies
    /// that resolved to a report in the set.
    pub(crate) fn from_reports(reports: &[LinkReport]) -> Self {
        // Stable node index per ecosystem:name key.
        let mut index_of: BTreeMap<String, usize> = BTreeMap::new();
        let mut nodes: Vec<Node> = Vec::new();

        for report in reports {
            let key = node_key(
                &report.locked.ecosystem.to_string(),
                &report.artifact.package.name,
            );
            if index_of.contains_key(&key) {
                continue;
            }
            index_of.insert(key, nodes.len());
            nodes.push(Node {
                name: report.artifact.package.name.clone(),
                version: report.artifact.package.version.clone(),
                caps: capability_summary(report),
                risk: classify_risk(report),
                depth: 0,
            });
        }

        // Edges: each report's dependency specs -> the matching child node.
        let mut edges: Vec<(usize, usize)> = Vec::new();
        let mut edge_seen: BTreeSet<(usize, usize)> = BTreeSet::new();
        for report in reports {
            let from_key = node_key(
                &report.locked.ecosystem.to_string(),
                &report.artifact.package.name,
            );
            let Some(&from) = index_of.get(&from_key) else {
                continue;
            };
            let deps = report
                .artifact
                .dependencies
                .iter()
                .chain(report.artifact.optional_dependencies.iter())
                .chain(report.artifact.peer_dependencies.iter());
            for dep in deps {
                if let Some(child_key) = dependency_node_key(dep) {
                    if let Some(&to) = index_of.get(&child_key) {
                        if from != to && edge_seen.insert((from, to)) {
                            edges.push((from, to));
                        }
                    }
                }
            }
        }

        let mut graph = Self { nodes, edges };
        graph.assign_depths();
        graph
    }

    /// Assign each node a BFS depth from the set of roots (nodes with no
    /// incoming edge). Used to lay nodes out in horizontal layers.
    fn assign_depths(&mut self) {
        let n = self.nodes.len();
        if n == 0 {
            return;
        }
        let mut indegree = vec![0usize; n];
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &(from, to) in &self.edges {
            indegree[to] += 1;
            adjacency[from].push(to);
        }

        let mut queue: VecDeque<usize> = VecDeque::new();
        for (idx, &deg) in indegree.iter().enumerate() {
            if deg == 0 {
                self.nodes[idx].depth = 0;
                queue.push_back(idx);
            }
        }
        // If every node has an incoming edge (pure cycle), seed node 0 as root.
        if queue.is_empty() {
            self.nodes[0].depth = 0;
            queue.push_back(0);
        }

        let mut visited = vec![false; n];
        while let Some(node) = queue.pop_front() {
            if visited[node] {
                continue;
            }
            visited[node] = true;
            let depth = self.nodes[node].depth;
            for &child in &adjacency[node] {
                if self.nodes[child].depth < depth + 1 {
                    self.nodes[child].depth = depth + 1;
                }
                if !visited[child] {
                    queue.push_back(child);
                }
            }
        }
    }
}

fn node_key(ecosystem: &str, name: &str) -> String {
    format!("{ecosystem}:{name}")
}

/// Turn a dependency spec string such as `npm:left-pad@1.3.0`,
/// `npm:left-pad`, or `pypi:idna[all] @ https://...` into the
/// "ecosystem:name" key used to look up the child node. Returns `None` if the
/// string has no recognizable `ecosystem:` prefix.
fn dependency_node_key(dep: &str) -> Option<String> {
    let (ecosystem, rest) = dep.split_once(':')?;
    // Strip a direct-url suffix (" @ url"), then any extras and version.
    let rest = rest.split(" @ ").next().unwrap_or(rest);
    let rest = rest.split('[').next().unwrap_or(rest);
    // Version separator: for scoped npm names the name itself starts with '@',
    // so use the LAST '@' as the version delimiter.
    let name = match rest.strip_prefix('@') {
        Some(tail) => match tail.rfind('@') {
            Some(at) => &rest[..at + 1],
            None => rest,
        },
        None => rest.split('@').next().unwrap_or(rest),
    };
    Some(node_key(ecosystem.trim(), name.trim()))
}

// ----------------------------------------------------------------------------
// Rendering
// ----------------------------------------------------------------------------

const NODE_W: f32 = 230.0;
const NODE_H: f32 = 64.0;
const H_GAP: f32 = 90.0; // horizontal gap between layers
const V_GAP: f32 = 24.0; // vertical gap between nodes in a layer
const MARGIN: f32 = 40.0;
const TEXT_SCALE: u32 = 2; // bitmap font pixel size

/// Lay the graph out in horizontal layers (by BFS depth) and rasterize it to a
/// `Pixmap`. Pure-Rust: rectangles + lines + a built-in bitmap font, no system
/// fonts or external tools.
pub(crate) fn render_graph(graph: &DependencyGraph) -> Pixmap {
    // Group node indices by depth layer.
    let max_depth = graph.nodes.iter().map(|n| n.depth).max().unwrap_or(0);
    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_depth + 1];
    for (idx, node) in graph.nodes.iter().enumerate() {
        layers[node.depth].push(idx);
    }

    // Position each node. Each layer is a column; nodes stack vertically.
    let mut positions: Vec<(f32, f32)> = vec![(0.0, 0.0); graph.nodes.len()];
    let mut max_rows = 1usize;
    for (depth, layer) in layers.iter().enumerate() {
        max_rows = max_rows.max(layer.len().max(1));
        let x = MARGIN + depth as f32 * (NODE_W + H_GAP);
        for (row, &node_idx) in layer.iter().enumerate() {
            let y = MARGIN + row as f32 * (NODE_H + V_GAP);
            positions[node_idx] = (x, y);
        }
    }

    let width = (MARGIN * 2.0 + (max_depth as f32 + 1.0) * NODE_W + max_depth as f32 * H_GAP)
        .ceil()
        .max(NODE_W + MARGIN * 2.0) as u32;
    let height =
        (MARGIN * 2.0 + max_rows as f32 * NODE_H + (max_rows as f32 - 1.0).max(0.0) * V_GAP)
            .ceil()
            .max(NODE_H + MARGIN * 2.0) as u32;

    let mut pixmap = Pixmap::new(width.max(1), height.max(1)).expect("non-zero pixmap dimensions");
    pixmap.fill(Color::from_rgba8(0xFA, 0xFA, 0xFA, 0xFF));

    // Edges first (so nodes draw on top).
    draw_edges(&mut pixmap, graph, &positions);

    // Nodes.
    for (idx, node) in graph.nodes.iter().enumerate() {
        let (x, y) = positions[idx];
        draw_node(&mut pixmap, node, x, y);
    }

    pixmap
}

fn draw_edges(pixmap: &mut Pixmap, graph: &DependencyGraph, positions: &[(f32, f32)]) {
    let mut paint = Paint::default();
    paint.set_color(Color::from_rgba8(0x9E, 0x9E, 0x9E, 0xFF));
    paint.anti_alias = true;
    let stroke = Stroke {
        width: 1.5,
        ..Stroke::default()
    };

    for &(from, to) in &graph.edges {
        let (fx, fy) = positions[from];
        let (tx, ty) = positions[to];
        // From right edge of parent to left edge of child.
        let start = (fx + NODE_W, fy + NODE_H / 2.0);
        let end = (tx, ty + NODE_H / 2.0);
        let mut pb = PathBuilder::new();
        pb.move_to(start.0, start.1);
        pb.line_to(end.0, end.1);
        if let Some(path) = pb.finish() {
            pixmap.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
        }
    }
}

fn draw_node(pixmap: &mut Pixmap, node: &Node, x: f32, y: f32) {
    // Filled, risk-colored body.
    if let Some(rect) = Rect::from_xywh(x, y, NODE_W, NODE_H) {
        let mut paint = Paint::default();
        paint.set_color(node.risk.color());
        paint.anti_alias = true;
        pixmap.fill_rect(rect, &paint, Transform::identity(), None);

        // Dark border, stroked as a closed rectangular path.
        let mut border = Paint::default();
        border.set_color(Color::from_rgba8(0x33, 0x33, 0x33, 0xFF));
        border.anti_alias = true;
        let stroke = Stroke {
            width: 1.5,
            ..Stroke::default()
        };
        let mut pb = PathBuilder::new();
        pb.move_to(x, y);
        pb.line_to(x + NODE_W, y);
        pb.line_to(x + NODE_W, y + NODE_H);
        pb.line_to(x, y + NODE_H);
        pb.close();
        if let Some(path) = pb.finish() {
            pixmap.stroke_path(&path, &border, &stroke, Transform::identity(), None);
        }
    }

    let text_color = Color::from_rgba8(0x11, 0x11, 0x11, 0xFF);
    // "name version" header, then the capability summary on a second line.
    draw_text(
        pixmap,
        &node.header(),
        x + 8.0,
        y + 14.0,
        TEXT_SCALE,
        text_color,
    );
    draw_text(
        pixmap,
        &node.caps,
        x + 8.0,
        y + 38.0,
        TEXT_SCALE,
        Color::from_rgba8(0x22, 0x22, 0x22, 0xFF),
    );
}

/// Draw a string with the built-in 5x7 bitmap font at the given top-left origin.
/// `scale` is the pixel size of one font cell pixel. Text is clipped to the
/// node width by truncation.
fn draw_text(pixmap: &mut Pixmap, text: &str, x: f32, y: f32, scale: u32, color: Color) {
    let cell_w = (FONT_W as u32 + 1) * scale; // 1px inter-glyph gap
    let max_chars = ((NODE_W - 16.0) as u32 / cell_w).max(1) as usize;
    let mut paint = Paint::default();
    paint.set_color(color);
    paint.anti_alias = false;

    let mut cursor_x = x;
    for ch in text.chars().take(max_chars) {
        let glyph = glyph_bitmap(ch);
        for (row, bits) in glyph.iter().enumerate() {
            for col in 0..FONT_W {
                if bits & (1 << (FONT_W - 1 - col)) != 0 {
                    let px = cursor_x + (col as u32 * scale) as f32;
                    let py = y + (row as u32 * scale) as f32;
                    if let Some(rect) = Rect::from_xywh(px, py, scale as f32, scale as f32) {
                        pixmap.fill_rect(rect, &paint, Transform::identity(), None);
                    }
                }
            }
        }
        cursor_x += cell_w as f32;
    }
}

// ----------------------------------------------------------------------------
// Built-in 5x7 bitmap font (printable ASCII subset we need for labels).
// Each glyph is 7 rows; the low 5 bits of each byte are the pixel columns
// (MSB = leftmost). Unknown characters render as a small box.
// ----------------------------------------------------------------------------

const FONT_W: usize = 5;

fn glyph_bitmap(ch: char) -> [u8; 7] {
    match ch.to_ascii_uppercase() {
        ' ' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        'A' => [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'B' => [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
        'C' => [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
        'D' => [0x1C, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1C],
        'E' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
        'F' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
        'G' => [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F],
        'H' => [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'I' => [0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
        'J' => [0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C],
        'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
        'M' => [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
        'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        'O' => [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'P' => [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
        'Q' => [0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D],
        'R' => [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
        'S' => [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
        'T' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
        'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11],
        'X' => [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
        'Y' => [0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04],
        'Z' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F],
        '0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        '1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        '2' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
        '3' => [0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E],
        '4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        '5' => [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
        '6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        '7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        '8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        '9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
        '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C],
        '-' => [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
        '_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F],
        '@' => [0x0E, 0x11, 0x17, 0x15, 0x17, 0x10, 0x0E],
        '/' => [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
        '+' => [0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00],
        ':' => [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00],
        '[' => [0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E],
        ']' => [0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E],
        _ => [0x00, 0x1F, 0x11, 0x11, 0x11, 0x1F, 0x00], // box for unknown
    }
}

/// A unique temporary directory that is best-effort removed on drop. Used purely
/// as a sandboxed `LinkOptions::project_dir` so `omc graph` never writes into the
/// user's project.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new() -> Result<Self, OmcRegistryError> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("omc-graph-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
