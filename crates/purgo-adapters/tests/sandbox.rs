#![cfg(feature = "sandbox")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use purgo_adapters::{MagicFormatDetector, PngDisarmer, SandboxDisarmer, WasmtimeSandbox};
use purgo_application::DisarmService;
use purgo_domain::{
    Artifact, DisarmFile, DisarmRequest, Disarmer, FileFormat, FormatDetector, Policy, Sandbox,
};
use wasmtime::{Engine, Module};

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels under the workspace root")
        .to_path_buf()
}

fn guest_wasm_path() -> PathBuf {
    let root = workspace_root();
    let status = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "purgo-wasm-guest",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
        ])
        .status()
        .expect("failed to spawn cargo to build the wasm guest");
    assert!(status.success(), "building the wasm guest failed");

    root.join("target/wasm32-unknown-unknown/release/purgo_wasm_guest.wasm")
}

fn guest_wasm_bytes() -> Vec<u8> {
    let path = guest_wasm_path();
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("cannot read guest wasm at {}: {e}", path.display()))
}

fn load_sandbox() -> WasmtimeSandbox {
    WasmtimeSandbox::new(&guest_wasm_bytes()).expect("guest wasm must compile")
}

fn png_with_hidden_text() -> Vec<u8> {
    let mut v = SIGNATURE.to_vec();
    let mut push = |kind: &[u8; 4], data: &[u8]| {
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(kind);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0, 0, 0, 0]);
    };
    push(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
    push(b"tEXt", b"Comment\x00hidden-sandbox-payload");
    push(b"IDAT", &[0x78, 0x9c, 0x00]);
    push(b"IEND", &[]);
    v
}

#[test]
fn guest_module_has_no_imports() {
    let engine = Engine::default();
    let module = Module::new(&engine, guest_wasm_bytes()).expect("guest wasm must compile");
    let imports: Vec<_> = module.imports().collect();
    assert!(
        imports.is_empty(),
        "the sandbox guest must import nothing (no WASI, no host fns); found: {:?}",
        imports
            .iter()
            .map(|i| (i.module(), i.name()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn sandboxed_png_disarm_matches_in_process() {
    let input = png_with_hidden_text();
    let policy = Policy::strict();

    let in_process = PngDisarmer::new()
        .disarm(&Artifact::new(input.clone()), &policy)
        .expect("in-process disarm succeeds");

    let sandboxed = load_sandbox()
        .run_disarm(FileFormat::Png, &input, &policy)
        .expect("sandboxed disarm succeeds");

    assert_eq!(
        sandboxed.bytes, in_process.bytes,
        "sandbox and in-process must rebuild identical bytes"
    );

    assert_eq!(sandboxed.removed, in_process.removed);

    assert!(!sandboxed
        .bytes
        .windows(b"hidden-sandbox-payload".len())
        .any(|w| w == b"hidden-sandbox-payload"));
    assert!(sandboxed.bytes.starts_with(&SIGNATURE));
    assert_eq!(sandboxed.removed.len(), 1);
    assert!(sandboxed.removed[0].location.contains("tEXt"));
}

#[test]
fn sandbox_is_fail_closed_on_malformed_png() {
    let sandbox = load_sandbox();

    let err = sandbox
        .run_disarm(FileFormat::Png, &[0u8; 16], &Policy::strict())
        .unwrap_err();
    assert!(
        matches!(
            err,
            purgo_domain::DomainError::MalformedInput {
                format: FileFormat::Png,
                ..
            }
        ),
        "expected MalformedInput, got {err:?}"
    );
}

#[test]
fn sandbox_rejects_a_format_it_has_no_guest_for() {
    let sandbox = load_sandbox();
    let err = sandbox
        .run_disarm(FileFormat::Pdf, &[0u8; 4], &Policy::strict())
        .unwrap_err();
    assert_eq!(
        err,
        purgo_domain::DomainError::UnsupportedFormat(FileFormat::Pdf)
    );
}

#[test]
fn use_case_pipeline_runs_png_through_the_sandbox() {
    let sandbox: Arc<dyn Sandbox> = Arc::new(load_sandbox());
    let detector: Arc<dyn FormatDetector> = Arc::new(MagicFormatDetector::new());
    let disarmers: Vec<Arc<dyn Disarmer>> =
        vec![Arc::new(SandboxDisarmer::new(FileFormat::Png, sandbox))];
    let service = DisarmService::new(detector, disarmers);

    let receipt = service
        .execute(DisarmRequest::strict(Artifact::new(png_with_hidden_text())))
        .expect("sandboxed pipeline disarms the png");

    assert_eq!(receipt.clean.format(), FileFormat::Png);
    assert!(receipt.clean.bytes().starts_with(&SIGNATURE));
    assert_eq!(receipt.report.removed_count(), 1);
    assert!(!receipt
        .clean
        .bytes()
        .windows(b"hidden-sandbox-payload".len())
        .any(|w| w == b"hidden-sandbox-payload"));
}

const RUNAWAY_GUEST_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  ;; alloc just hands back a fixed offset so the host can write the input.
  (func (export "alloc") (param i32) (result i32)
    i32.const 0)
  (func (export "dealloc") (param i32 i32))
  ;; disarm never returns: a guest that loops forever must be trapped by the
  ;; fuel budget, not allowed to pin the host thread.
  (func (export "disarm") (param i32 i32 i32 i32) (result i64)
    (loop $spin
      br $spin)
    i64.const 0))
"#;

#[test]
fn fuel_budget_traps_a_runaway_guest() {
    let wasm = wat::parse_str(RUNAWAY_GUEST_WAT).expect("the runaway guest WAT must assemble");
    let sandbox = WasmtimeSandbox::new(&wasm).expect("the runaway guest must compile");

    let err = sandbox
        .run_disarm(FileFormat::Png, &[0u8; 8], &Policy::strict())
        .expect_err("a guest that loops forever must be trapped, not allowed to hang");
    assert!(
        matches!(err, purgo_domain::DomainError::SandboxFailure(_)),
        "exhausting the fuel budget must surface as a SandboxFailure, got {err:?}"
    );
}

const MEMORY_BOMB_GUEST_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  ;; Request a huge number of extra pages (≈ many GiB), well past the cap. With
  ;; the StoreLimits memory bound in place `memory.grow` fails (returns -1); we
  ;; turn that into an unreachable trap so the host observes a sandbox failure.
  (func (export "alloc") (param i32) (result i32)
    (if (i32.eq (memory.grow (i32.const 65535)) (i32.const -1))
      (then unreachable))
    i32.const 0)
  (func (export "dealloc") (param i32 i32))
  (func (export "disarm") (param i32 i32 i32 i32) (result i64)
    i64.const 0))
"#;

#[test]
fn memory_bound_denies_a_memory_bomb_guest() {
    let wasm =
        wat::parse_str(MEMORY_BOMB_GUEST_WAT).expect("the memory-bomb guest WAT must assemble");
    let sandbox = WasmtimeSandbox::new(&wasm).expect("the memory-bomb guest must compile");

    let err = sandbox
        .run_disarm(FileFormat::Png, &[0u8; 8], &Policy::strict())
        .expect_err("growing memory past the cap must be denied");
    assert!(
        matches!(err, purgo_domain::DomainError::SandboxFailure(_)),
        "exceeding the memory cap must surface as a SandboxFailure, got {err:?}"
    );
}
