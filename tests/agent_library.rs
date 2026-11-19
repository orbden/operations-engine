//! Runs the Python unit tests of the shared agent library
//! (`resources/agents/wcp_agent_lib.py`). The agents are Python, so the library
//! is tested in Python; this wrapper keeps it in `cargo test`.

use std::{path::Path, process::Command};

#[test]
fn the_agent_library_passes_its_python_tests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = match Command::new("python3")
        .arg("-I")
        .arg(root.join("tests/agent_lib/test_wcp_agent_lib.py"))
        .arg(root.join("resources/agents"))
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("python3 is not installed; the agent library tests were skipped");
            return;
        }
        Err(error) => panic!("python3: {error}"),
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
