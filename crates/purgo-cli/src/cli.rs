use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub input: PathBuf,

    pub output: PathBuf,

    pub report: Option<PathBuf>,

    pub sign: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArgError {
    Help,

    Missing(&'static str),

    Unexpected(String),
}

pub const USAGE: &str = "\
purgo — rebuild untrusted files into safe ones (Content Disarm & Reconstruction)

USAGE:
    purgo <INPUT> -o <OUTPUT> [--report <FILE>] [--sign <KEYFILE>]

ARGS:
    <INPUT>           File to sanitise

OPTIONS:
    -o, --output      Where to write the sanitised file (required)
    -r, --report      Write a JSON disarm report to this path
    -s, --sign        Sign the output with this Ed25519 seed key, writing a
                      detached signature to <OUTPUT>.sig
    -h, --help        Show this help
";

pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Args, ArgError> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut sign: Option<PathBuf> = None;

    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(ArgError::Help),
            "-o" | "--output" => {
                let value = it.next().ok_or(ArgError::Missing("--output value"))?;
                output = Some(PathBuf::from(value));
            }
            "-r" | "--report" => {
                let value = it.next().ok_or(ArgError::Missing("--report value"))?;
                report = Some(PathBuf::from(value));
            }
            "-s" | "--sign" => {
                let value = it.next().ok_or(ArgError::Missing("--sign value"))?;
                sign = Some(PathBuf::from(value));
            }
            other if other.starts_with('-') => {
                return Err(ArgError::Unexpected(other.to_string()));
            }
            positional => {
                if input.is_some() {
                    return Err(ArgError::Unexpected(positional.to_string()));
                }
                input = Some(PathBuf::from(positional));
            }
        }
    }

    Ok(Args {
        input: input.ok_or(ArgError::Missing("input file"))?,
        output: output.ok_or(ArgError::Missing("--output"))?,
        report,
        sign,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(args: &[&str]) -> Result<Args, ArgError> {
        parse(args.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn parses_input_output_and_report() {
        let args = parse_str(&["in.jpg", "-o", "out.jpg", "--report", "r.json"]).unwrap();
        assert_eq!(args.input, PathBuf::from("in.jpg"));
        assert_eq!(args.output, PathBuf::from("out.jpg"));
        assert_eq!(args.report, Some(PathBuf::from("r.json")));
        assert_eq!(args.sign, None);
    }

    #[test]
    fn parses_the_sign_key_file() {
        let args = parse_str(&["in.jpg", "-o", "out.jpg", "--sign", "key.bin"]).unwrap();
        assert_eq!(args.sign, Some(PathBuf::from("key.bin")));
        let short = parse_str(&["in.jpg", "-o", "out.jpg", "-s", "key.bin"]).unwrap();
        assert_eq!(short.sign, Some(PathBuf::from("key.bin")));
    }

    #[test]
    fn sign_requires_a_value() {
        assert_eq!(
            parse_str(&["in.jpg", "-o", "out.jpg", "--sign"]),
            Err(ArgError::Missing("--sign value"))
        );
    }

    #[test]
    fn output_is_required() {
        assert_eq!(parse_str(&["in.jpg"]), Err(ArgError::Missing("--output")));
    }

    #[test]
    fn rejects_unknown_flag() {
        assert_eq!(
            parse_str(&["in.jpg", "-o", "out.jpg", "--nope"]),
            Err(ArgError::Unexpected("--nope".to_string()))
        );
    }

    #[test]
    fn help_is_signalled() {
        assert_eq!(parse_str(&["-h"]), Err(ArgError::Help));
    }
}
