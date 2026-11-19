//! Every helper named in the "Shared helpers" table of CONTRIBUTING.md must still
//! be defined in the file the table gives, so the document cannot rot.

use std::{fs, path::Path};

#[test]
fn shared_helper_table_names_existing_definitions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let doc = fs::read_to_string(root.join("CONTRIBUTING.md")).expect("CONTRIBUTING.md");
    let section = doc
        .split("## Shared helpers")
        .nth(1)
        .expect("Shared helpers section")
        .split("\n## ")
        .next()
        .unwrap();
    let mut checked = 0;
    for row in section.lines().filter(|line| line.starts_with("| ")) {
        let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
        let [_, names, file] = cells[..] else {
            continue;
        };
        let Some(file) = file.strip_prefix('`').and_then(|f| f.strip_suffix('`')) else {
            continue; // header and separator rows
        };
        let source = fs::read_to_string(root.join(file)).unwrap_or_else(|_| panic!("{file}"));
        for name in names.split(',').map(|n| n.trim().trim_matches('`')) {
            let name = name.rsplit("::").next().unwrap();
            let rust = format!("fn {name}(");
            let shell = format!("{name}()");
            assert!(
                source.contains(&rust) || source.contains(&shell),
                "{name} is not defined in {file}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 15, "table not parsed, checked {checked}");
}
