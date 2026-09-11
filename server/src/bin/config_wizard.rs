//! Interactive entry point for the deploy-time config wizard
//! (`cargo run --features wizard --bin dratchetd-config-wizard`).
//!
//! Argument parsing and file I/O only — the actual answer-collection and
//! rendering logic lives in `dratchet_server::wizard`, which is unit-tested
//! independent of this binary.

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use dratchet_server::wizard::{collect_answers_interactive, render_values_override, WizardAnswers};

#[derive(Parser, Debug)]
#[command(
    name = "dratchetd-config-wizard",
    about = "Generate a Helm values override for chart/dratchet-server"
)]
struct Args {
    /// Where to write the generated values override file.
    #[arg(short, long, default_value = "dratchet-values.generated.yaml")]
    output: PathBuf,

    /// Skip the interactive prompts and read answers from this JSON file
    /// instead — a scripting/testing escape hatch (used by CI, which has no
    /// PTY to drive real prompts with), not the primary UX.
    #[arg(long)]
    non_interactive: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();

    let answers = match args.non_interactive {
        Some(path) => {
            let bytes = fs::read(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            serde_json::from_slice::<WizardAnswers>(&bytes)
                .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
        }
        None => collect_answers_interactive(),
    };

    let rendered = render_values_override(&answers);
    fs::write(&args.output, &rendered)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", args.output.display()));

    println!("Wrote {}", args.output.display());
    println!();
    println!("Apply it with:");
    println!(
        "  helm upgrade --install dratchet chart/dratchet-server -f {}",
        args.output.display()
    );
}
