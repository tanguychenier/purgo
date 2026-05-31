mod cli;
mod json;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use purgo_adapters::{
    Ed25519Signer, JpegDisarmer, MagicFormatDetector, OoxmlDisarmer, PdfDisarmer, PngDisarmer,
    ZipDisarmer,
};
use purgo_application::{DisarmService, SigningDisarmService};
use purgo_domain::{
    Artifact, DisarmAndSign, DisarmFile, DisarmReceipt, DisarmRequest, Disarmer, FormatDetector,
    Signer,
};

use cli::{ArgError, Args};

fn main() -> ExitCode {
    let args = match cli::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(ArgError::Help) => {
            print!("{}", cli::USAGE);
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("error: {err:?}\n\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purgo: {err}");
            ExitCode::FAILURE
        }
    }
}

fn build_service() -> DisarmService {
    let detector: Arc<dyn FormatDetector> = Arc::new(MagicFormatDetector::new());
    let disarmers: Vec<Arc<dyn Disarmer>> = vec![
        Arc::new(JpegDisarmer::new()),
        Arc::new(PngDisarmer::new()),
        Arc::new(PdfDisarmer::new()),
        Arc::new(OoxmlDisarmer::new()),
        Arc::new(ZipDisarmer::new()),
    ];
    DisarmService::new(detector, disarmers)
}

fn run(args: &Args) -> Result<(), String> {
    let bytes =
        fs::read(&args.input).map_err(|e| format!("cannot read {}: {e}", args.input.display()))?;
    let artifact = Artifact::named(args.input.display().to_string(), bytes);
    let request = DisarmRequest::strict(artifact);

    let receipt = match &args.sign {
        Some(key_path) => run_signed(args, request, key_path)?,
        None => build_service()
            .execute(request)
            .map_err(|e| e.to_string())?,
    };

    write_outputs(args, &receipt)?;

    eprintln!(
        "purgo: {} -> {} ({} item(s) removed, {} -> {} bytes)",
        args.input.display(),
        args.output.display(),
        receipt.report.removed_count(),
        receipt.report.original_size,
        receipt.report.sanitized_size,
    );
    Ok(())
}

fn run_signed(
    args: &Args,
    request: DisarmRequest,
    key_path: &Path,
) -> Result<DisarmReceipt, String> {
    let signer: Arc<dyn Signer> =
        Arc::new(Ed25519Signer::from_seed_file(key_path).map_err(|e| e.to_string())?);
    let disarm: Arc<dyn DisarmFile + Send + Sync> = Arc::new(build_service());
    let use_case = SigningDisarmService::new(disarm, signer);

    let signed = use_case
        .execute_signed(request)
        .map_err(|e| e.to_string())?;

    let sig_path = sibling_path(&args.output, ".sig");
    fs::write(&sig_path, signed.signature.bytes())
        .map_err(|e| format!("cannot write signature {}: {e}", sig_path.display()))?;

    let pub_path = sibling_path(&args.output, ".pub");
    fs::write(&pub_path, signed.public_key.bytes())
        .map_err(|e| format!("cannot write public key {}: {e}", pub_path.display()))?;

    eprintln!(
        "purgo: signed output -> {} (public key -> {})",
        sig_path.display(),
        pub_path.display()
    );
    Ok(signed.receipt)
}

fn write_outputs(args: &Args, receipt: &DisarmReceipt) -> Result<(), String> {
    fs::write(&args.output, receipt.clean.bytes())
        .map_err(|e| format!("cannot write {}: {e}", args.output.display()))?;

    if let Some(report_path) = &args.report {
        fs::write(report_path, json::report_to_json(&receipt.report))
            .map_err(|e| format!("cannot write report {}: {e}", report_path.display()))?;
    }
    Ok(())
}

fn sibling_path(output: &Path, suffix: &str) -> PathBuf {
    let mut name = output.as_os_str().to_os_string();
    name.push(OsString::from(suffix));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_path_appends_suffix_keeping_extension() {
        assert_eq!(
            sibling_path(Path::new("/tmp/out.jpg"), ".sig"),
            PathBuf::from("/tmp/out.jpg.sig")
        );
        assert_eq!(
            sibling_path(Path::new("clean"), ".pub"),
            PathBuf::from("clean.pub")
        );
    }
}
