// elide-import: OCI image pull and ext4 image creation for Elide volumes.
//
// Pulls a public OCI image from a container registry, extracts a rootfs,
// converts it to an ext4 disk image, and imports it as a readonly Elide
// volume using elide-core::import::import_image.
//
// This binary carries the heavy async dependencies (tokio, oci-client,
// ocirender) that are not appropriate in the lightweight elide volume binary.

use clap::Parser;

#[derive(Parser)]
#[command(about = "Import an OCI image as a readonly Elide volume")]
struct Args {
    /// OCI image reference (e.g. ubuntu:22.04, ghcr.io/org/image:tag)
    image: String,

    /// Path to the volume directory to create (e.g. volumes/ubuntu-22.04)
    vol_dir: String,

    /// Disk image size (e.g. 4G, 2048M). Auto-detected if not specified.
    #[arg(long)]
    size: Option<String>,

    /// Target architecture (e.g. amd64, arm64). Defaults to host arch.
    #[arg(long)]
    arch: Option<String>,
}

fn main() {
    let _args = Args::parse();
    eprintln!("elide-import: OCI pull not yet implemented");
    std::process::exit(1);
}
