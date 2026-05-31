use std::io::{Cursor, Read, Write};

use lopdf::{dictionary, Document, Object, Stream};
use purgo_adapters::{JpegDisarmer, MagicFormatDetector, OoxmlDisarmer, PdfDisarmer, PngDisarmer};
use purgo_domain::{Artifact, Disarmer, FileFormat, FormatDetector, Policy, ThreatClass};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn jpeg_with_exif() -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];
    let exif = b"Exif\x00\x00SENSITIVE-GPS";
    v.extend_from_slice(&[0xFF, 0xE1]);
    v.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(exif);
    v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0x10, 0x20, 0xFF, 0xD9]);
    v
}

#[test]
fn detector_and_jpeg_disarmer_agree_and_strip_exif() {
    let artifact = Artifact::new(jpeg_with_exif());

    let format = MagicFormatDetector::new().detect(&artifact);
    assert_eq!(format, FileFormat::Jpeg);

    let disarmer = JpegDisarmer::new();
    assert_eq!(disarmer.format(), format);

    let out = disarmer.disarm(&artifact, &Policy::strict()).unwrap();
    assert!(!contains(&out.bytes, b"SENSITIVE-GPS"));
    assert_eq!(out.removed.len(), 1);
}

#[test]
fn png_disarmer_is_selected_for_png_signature() {
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend_from_slice(b"IEND");
    bytes.extend_from_slice(&[0, 0, 0, 0]);

    let artifact = Artifact::new(bytes);
    assert_eq!(
        MagicFormatDetector::new().detect(&artifact),
        FileFormat::Png
    );
    let out = PngDisarmer::new()
        .disarm(&artifact, &Policy::strict())
        .unwrap();
    assert!(out.bytes.starts_with(&[0x89, b'P', b'N', b'G']));
}

fn pdf_with_open_action() -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let content_id = doc.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf (VisibleBody) Tj ET".to_vec(),
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
        "Type" => "Action", "S" => "JavaScript", "JS" => "app.alert('pwn');",
    });
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog", "Pages" => pages_id, "OpenAction" => js_id,
    });
    doc.trailer.set("Root", catalog_id);
    let mut buf = Vec::new();
    doc.save_to(&mut buf).expect("fixture pdf must serialise");
    buf
}

#[test]
fn detector_and_pdf_disarmer_agree_and_strip_open_action() {
    let artifact = Artifact::new(pdf_with_open_action());

    let format = MagicFormatDetector::new().detect(&artifact);
    assert_eq!(format, FileFormat::Pdf);

    let disarmer = PdfDisarmer::new();
    assert_eq!(disarmer.format(), format);

    let out = disarmer.disarm(&artifact, &Policy::strict()).unwrap();
    assert!(!contains(&out.bytes, b"OpenAction"), "OpenAction stripped");
    assert!(!contains(&out.bytes, b"app.alert"), "JavaScript stripped");
    assert!(contains(&out.bytes, b"VisibleBody"), "page text kept");
    assert!(!out.removed.is_empty(), "a removal must be recorded");

    let reparsed = Document::load_mem(&out.bytes).expect("output is valid pdf");
    assert_eq!(reparsed.get_pages().len(), 1);
}

fn docx_with_macro() -> Vec<u8> {
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
    part("word/document.xml", b"<w:document>BODY-TEXT</w:document>");
    part("word/vbaProject.bin", b"INTEGRATION-MACRO-PAYLOAD");
    part(
        "word/_rels/document.xml.rels",
        br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>"#,
    );
    zip.finish().unwrap().into_inner()
}

#[test]
fn detector_and_ooxml_disarmer_agree_and_strip_macros() {
    let artifact = Artifact::new(docx_with_macro());

    let format = MagicFormatDetector::new().detect(&artifact);
    assert_eq!(format, FileFormat::Ooxml);

    let disarmer = OoxmlDisarmer::new();
    assert_eq!(disarmer.format(), format);

    let out = disarmer.disarm(&artifact, &Policy::strict()).unwrap();
    assert!(out
        .removed
        .iter()
        .any(|r| r.class == ThreatClass::ActiveContent));

    let mut rebuilt = ZipArchive::new(Cursor::new(out.bytes.clone())).expect("output is valid zip");
    let names: Vec<String> = (0..rebuilt.len())
        .map(|i| rebuilt.by_index(i).unwrap().name().to_owned())
        .collect();
    assert!(names.iter().any(|n| n == "word/document.xml"));
    assert!(!names.iter().any(|n| n.contains("vbaProject")));
    let mut body = String::new();
    rebuilt
        .by_name("word/document.xml")
        .unwrap()
        .read_to_string(&mut body)
        .unwrap();
    assert!(body.contains("BODY-TEXT"));
}
