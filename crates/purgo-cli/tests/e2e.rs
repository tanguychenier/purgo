use std::fs;
use std::process::Command;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn sample_jpeg_with_exif() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];
    let payload = b"Exif\x00\x00HIDDEN-METADATA";
    v.extend_from_slice(&[0xFF, 0xE1]);
    v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x04, 0x12, 0x34]);
    v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0xAA, 0xBB, 0xFF, 0xD9]);
    v
}

#[test]
fn cli_strips_exif_and_writes_report() {
    let dir = std::env::temp_dir().join(format!("purgo-e2e-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.jpg");
    let output = dir.join("out.jpg");
    let report = dir.join("report.json");
    fs::write(&input, sample_jpeg_with_exif()).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_purgo"))
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .arg("--report")
        .arg(&report)
        .status()
        .expect("failed to spawn purgo binary");
    assert!(status.success(), "purgo should exit successfully");

    let cleaned = fs::read(&output).unwrap();
    assert_eq!(&cleaned[0..2], &[0xFF, 0xD8], "SOI preserved");
    assert!(!contains(&cleaned, b"HIDDEN-METADATA"), "EXIF removed");
    assert_eq!(
        &cleaned[cleaned.len() - 2..],
        &[0xFF, 0xD9],
        "EOI preserved"
    );

    let report_json = fs::read_to_string(&report).unwrap();
    assert!(report_json.contains("\"format\": \"jpeg\""));
    assert!(report_json.contains("APP1"));

    let _ = fs::remove_dir_all(&dir);
}

fn sample_pdf_with_active_content() -> Vec<u8> {
    use lopdf::{dictionary, Document, Object, Stream};

    let mut doc = Document::with_version("1.5");
    let content_id = doc.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf (E2EVisibleText) Tj ET".to_vec(),
    ));
    let pages_id = doc.new_object_id();
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
    });
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        }),
    );
    let js_id = doc.add_object(dictionary! {
        "Type" => "Action", "S" => "JavaScript", "JS" => "app.alert('e2e-pwn');",
    });
    let ef_id = doc.add_object(Stream::new(
        dictionary! { "Type" => "EmbeddedFile" },
        b"E2E-EMBEDDED-PAYLOAD".to_vec(),
    ));
    let filespec_id = doc.add_object(dictionary! {
        "Type" => "Filespec",
        "F" => Object::string_literal("payload.bin"),
        "EF" => dictionary! { "F" => ef_id },
    });
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
        "OpenAction" => js_id,
        "Names" => dictionary! {
            "EmbeddedFiles" => dictionary! {
                "Names" => vec![Object::string_literal("payload.bin"), filespec_id.into()],
            },
        },
    });
    doc.trailer.set("Root", catalog_id);
    let mut buf = Vec::new();
    doc.save_to(&mut buf).expect("fixture pdf must serialise");
    buf
}

#[test]
fn cli_disarms_pdf_active_content_and_embedded_file() {
    let dir = std::env::temp_dir().join(format!("purgo-e2e-pdf-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.pdf");
    let output = dir.join("out.pdf");
    let report = dir.join("report.json");
    fs::write(&input, sample_pdf_with_active_content()).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_purgo"))
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .arg("--report")
        .arg(&report)
        .status()
        .expect("failed to spawn purgo binary");
    assert!(status.success(), "purgo should exit successfully");

    let cleaned = fs::read(&output).unwrap();
    assert!(cleaned.starts_with(b"%PDF-"), "output is a PDF");
    assert!(contains(&cleaned, b"E2EVisibleText"), "page text preserved");
    assert!(!contains(&cleaned, b"app.alert"), "JavaScript removed");
    assert!(!contains(&cleaned, b"OpenAction"), "OpenAction removed");
    assert!(
        !contains(&cleaned, b"E2E-EMBEDDED-PAYLOAD"),
        "embedded file removed"
    );

    let report_json = fs::read_to_string(&report).unwrap();
    assert!(report_json.contains("\"format\": \"pdf\""));
    assert!(report_json.contains("\"modified\": true"));
    assert!(report_json.contains("\"active-content\""));
    assert!(report_json.contains("\"embedded-file\""));

    let _ = fs::remove_dir_all(&dir);
}

fn sample_docx_with_macro_and_external() -> Vec<u8> {
    use std::io::{Cursor, Write};
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut part = |name: &str, data: &[u8]| {
        zip.start_file(name, opts).unwrap();
        zip.write_all(data).unwrap();
    };
    part(
        "[Content_Types].xml",
        br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#,
    );
    part(
        "_rels/.rels",
        br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#,
    );
    part(
        "word/document.xml",
        b"<w:document>E2E-DOCX-BODY</w:document>",
    );
    part("word/vbaProject.bin", b"E2E-DOCX-MACRO-PAYLOAD");
    part(
        "word/_rels/document.xml.rels",
        br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject" Target="vbaProject.bin"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://evil.example/x" TargetMode="External"/>
</Relationships>"#,
    );
    zip.finish().unwrap().into_inner()
}

#[test]
fn cli_disarms_docx_macros_and_external_links() {
    let dir = std::env::temp_dir().join(format!("purgo-e2e-docx-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.docx");
    let output = dir.join("out.docx");
    let report = dir.join("report.json");
    fs::write(&input, sample_docx_with_macro_and_external()).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_purgo"))
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .arg("--report")
        .arg(&report)
        .status()
        .expect("failed to spawn purgo binary");
    assert!(status.success(), "purgo should exit successfully");

    let cleaned = fs::read(&output).unwrap();
    assert!(
        cleaned.starts_with(&[0x50, 0x4B]),
        "output is a ZIP package"
    );

    use std::io::{Cursor, Read};
    let mut archive = zip::ZipArchive::new(Cursor::new(cleaned)).expect("output is a valid zip");
    let names: Vec<String> = (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_owned())
        .collect();
    assert!(names.iter().any(|n| n == "word/document.xml"));
    assert!(
        !names.iter().any(|n| n.contains("vbaProject")),
        "VBA macro part removed, got {names:?}"
    );

    let read_part = |archive: &mut zip::ZipArchive<Cursor<Vec<u8>>>, name: &str| -> String {
        let mut s = String::new();
        archive
            .by_name(name)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        s
    };
    assert!(read_part(&mut archive, "word/document.xml").contains("E2E-DOCX-BODY"));
    let rels = read_part(&mut archive, "word/_rels/document.xml.rels");
    assert!(!rels.contains("vbaProject"), "macro relationship removed");
    assert!(!rels.contains("evil.example"), "external link removed");

    let report_json = fs::read_to_string(&report).unwrap();
    assert!(report_json.contains("\"format\": \"ooxml\""));
    assert!(report_json.contains("\"modified\": true"));
    assert!(report_json.contains("\"active-content\""));
    assert!(report_json.contains("\"external-reference\""));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_signs_output_and_signature_verifies() {
    use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};

    let dir = std::env::temp_dir().join(format!("purgo-e2e-sign-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.jpg");
    let output = dir.join("out.jpg");
    let key = dir.join("signing.key");
    fs::write(&input, sample_jpeg_with_exif()).unwrap();

    let seed = [42u8; 32];
    fs::write(&key, seed).unwrap();
    let verifying_key: VerifyingKey = SigningKey::from_bytes(&seed).verifying_key();

    let status = Command::new(env!("CARGO_BIN_EXE_purgo"))
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .arg("--sign")
        .arg(&key)
        .status()
        .expect("failed to spawn purgo binary");
    assert!(status.success(), "purgo should exit successfully");

    let cleaned = fs::read(&output).unwrap();
    let sig_bytes = fs::read(dir.join("out.jpg.sig")).expect("detached signature must exist");
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64-byte signature");
    let signature = Signature::from_bytes(&sig_arr);

    assert!(
        verifying_key.verify(&cleaned, &signature).is_ok(),
        "the detached signature must verify against the cleaned output"
    );
    assert!(
        verifying_key
            .verify(b"some other bytes", &signature)
            .is_err(),
        "the signature must not verify against different bytes"
    );

    let pub_bytes = fs::read(dir.join("out.jpg.pub")).expect("public key must be written");
    let pub_arr: [u8; 32] = pub_bytes.as_slice().try_into().expect("32-byte public key");
    let emitted_key = VerifyingKey::from_bytes(&pub_arr).expect("emitted public key is valid");
    assert_eq!(
        emitted_key, verifying_key,
        "the emitted public key must match the signing key's public half"
    );
    assert!(
        emitted_key.verify(&cleaned, &signature).is_ok(),
        "the signature must verify against the emitted public key"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_rejects_a_bad_signing_key_file() {
    let dir = std::env::temp_dir().join(format!("purgo-e2e-badkey-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.jpg");
    let output = dir.join("out.jpg");
    let key = dir.join("too-short.key");
    fs::write(&input, sample_jpeg_with_exif()).unwrap();
    fs::write(&key, [0u8; 4]).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_purgo"))
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .arg("--sign")
        .arg(&key)
        .status()
        .expect("failed to spawn purgo binary");
    assert!(
        !status.success(),
        "purgo must fail closed on an unusable signing key"
    );
    assert!(
        !dir.join("out.jpg.sig").exists(),
        "no signature should be written when signing fails"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_reports_help_and_succeeds() {
    let output = Command::new(env!("CARGO_BIN_EXE_purgo"))
        .arg("--help")
        .output()
        .expect("failed to spawn purgo binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("USAGE"));
}
