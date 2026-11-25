use std::path::Path;

fn main() {
    let dist_dir = Path::new("../../web/dist");
    if !dist_dir.exists() {
        let _ = std::fs::create_dir_all(dist_dir);
    }
    println!("cargo:rerun-if-changed=../../web/dist");
}
