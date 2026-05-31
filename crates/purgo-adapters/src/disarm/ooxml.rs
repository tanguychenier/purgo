use std::io::{Cursor, Read};
use std::panic::{catch_unwind, AssertUnwindSafe};

use purgo_domain::{
    Artifact, DisarmOutput, Disarmer, DomainError, FileFormat, Policy, RemovedItem, ThreatClass,
};
use quick_xml::events::Event;
use quick_xml::{Reader, Writer, XmlVersion};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

#[derive(Debug, Default, Clone, Copy)]
pub struct OoxmlDisarmer;

impl OoxmlDisarmer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn malformed(reason: impl Into<String>) -> DomainError {
    DomainError::MalformedInput {
        format: FileFormat::Ooxml,
        reason: reason.into(),
    }
}

enum Decision {
    Keep,

    Drop(ThreatClass, String),

    Rewrite,
}

fn is_vba_project(name: &str) -> bool {
    base_name(name)
        .to_ascii_lowercase()
        .starts_with("vbaproject")
        && name.to_ascii_lowercase().ends_with(".bin")
}

fn is_embedded_ole(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("/embeddings/")
        || lower.starts_with("embeddings/")
        || base_name(&lower).starts_with("oleobject")
}

fn is_rels(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".rels")
}

fn base_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

fn decide(name: &str) -> Decision {
    if is_vba_project(name) {
        Decision::Drop(
            ThreatClass::ActiveContent,
            format!("VBA macro project '{name}'"),
        )
    } else if is_embedded_ole(name) {
        Decision::Drop(
            ThreatClass::ActiveContent,
            format!("embedded OLE object '{name}'"),
        )
    } else if is_rels(name) {
        Decision::Rewrite
    } else {
        Decision::Keep
    }
}

impl Disarmer for OoxmlDisarmer {
    fn format(&self) -> FileFormat {
        FileFormat::Ooxml
    }

    fn disarm(&self, artifact: &Artifact, _policy: &Policy) -> Result<DisarmOutput, DomainError> {
        let result = catch_unwind(AssertUnwindSafe(|| disarm_inner(artifact.bytes())));
        match result {
            Ok(inner) => inner,
            Err(_) => Err(malformed("parser panicked on hostile input")),
        }
    }
}

fn disarm_inner(data: &[u8]) -> Result<DisarmOutput, DomainError> {
    let mut archive = ZipArchive::new(Cursor::new(data))
        .map_err(|e| malformed(format!("cannot open ZIP container: {e}")))?;

    let mut writer = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    let mut removed: Vec<RemovedItem> = Vec::new();

    for i in 0..archive.len() {
        let (name, is_dir) = {
            let entry = archive
                .by_index(i)
                .map_err(|e| malformed(format!("cannot read ZIP entry {i}: {e}")))?;
            (entry.name().to_owned(), entry.is_dir())
        };

        if is_dir {
            let entry = archive
                .by_index(i)
                .map_err(|e| malformed(format!("cannot read ZIP entry {i}: {e}")))?;
            writer
                .raw_copy_file_rename(entry, name)
                .map_err(|e| malformed(format!("cannot copy directory entry: {e}")))?;
            continue;
        }

        match decide(&name) {
            Decision::Keep => {
                let entry = archive
                    .by_index(i)
                    .map_err(|e| malformed(format!("cannot read ZIP entry {i}: {e}")))?;
                writer
                    .raw_copy_file_rename(entry, &name)
                    .map_err(|e| malformed(format!("cannot copy part '{name}': {e}")))?;
            }
            Decision::Drop(class, detail) => {
                let entry = archive
                    .by_index(i)
                    .map_err(|e| malformed(format!("cannot read ZIP entry {i}: {e}")))?;
                let bytes_removed = entry.size() as usize;
                removed.push(RemovedItem::new(
                    format!("part {name}"),
                    class,
                    detail,
                    bytes_removed,
                ));
            }
            Decision::Rewrite => {
                let raw = read_entry(&mut archive, i, &name)?;
                let (cleaned, dropped) = sanitize_rels(&raw, &name)?;
                removed.extend(dropped);
                let options =
                    SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
                writer
                    .start_file(&name, options)
                    .map_err(|e| malformed(format!("cannot write part '{name}': {e}")))?;
                use std::io::Write as _;
                writer
                    .write_all(&cleaned)
                    .map_err(|e| malformed(format!("cannot write part '{name}': {e}")))?;
            }
        }
    }

    let cursor = writer
        .finish()
        .map_err(|e| malformed(format!("cannot finalise ZIP container: {e}")))?;
    Ok(DisarmOutput::new(cursor.into_inner(), removed))
}

const MAX_RELS_SIZE: u64 = 64 * 1024 * 1024;

fn read_entry(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    i: usize,
    name: &str,
) -> Result<Vec<u8>, DomainError> {
    let entry = archive
        .by_index(i)
        .map_err(|e| malformed(format!("cannot read part '{name}': {e}")))?;

    let mut buf = Vec::new();
    let read = entry
        .take(MAX_RELS_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| malformed(format!("cannot decompress part '{name}': {e}")))?;
    if read as u64 > MAX_RELS_SIZE {
        return Err(malformed(format!(
            "relationships part '{name}' is too large"
        )));
    }
    Ok(buf)
}

const ACTIVE_TYPE_SUFFIXES: &[&str] = &["oleobject", "vbaproject"];

fn sanitize_rels(raw: &[u8], part: &str) -> Result<(Vec<u8>, Vec<RemovedItem>), DomainError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| malformed(format!("relationships part '{part}' is not valid UTF-8")))?;

    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);

    let mut writer = Writer::new(Cursor::new(Vec::<u8>::new()));
    let mut removed: Vec<RemovedItem> = Vec::new();

    loop {
        let event = reader
            .read_event()
            .map_err(|e| malformed(format!("malformed relationships XML in '{part}': {e}")))?;
        match event {
            Event::Eof => break,
            Event::Start(ref e) | Event::Empty(ref e)
                if e.local_name().as_ref() == b"Relationship" =>
            {
                match classify_relationship(e)? {
                    Some((class, detail, size)) => {
                        removed.push(RemovedItem::new(
                            format!("part {part}"),
                            class,
                            detail,
                            size,
                        ));

                        if matches!(event, Event::Start(_)) {
                            skip_to_end(&mut reader, b"Relationship", part)?;
                        }
                    }
                    None => writer
                        .write_event(event)
                        .map_err(|e| malformed(format!("cannot re-emit '{part}': {e}")))?,
                }
            }
            other => writer
                .write_event(other)
                .map_err(|e| malformed(format!("cannot re-emit '{part}': {e}")))?,
        }
    }

    Ok((writer.into_inner().into_inner(), removed))
}

fn classify_relationship(
    element: &quick_xml::events::BytesStart,
) -> Result<Option<(ThreatClass, String, usize)>, DomainError> {
    let mut target_mode_external = false;
    let mut type_value = String::new();
    let mut id_value = String::new();

    for attr in element.attributes() {
        let attr = attr.map_err(|e| malformed(format!("malformed relationship attribute: {e}")))?;
        let key = attr.key.local_name();
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|e| malformed(format!("malformed relationship attribute value: {e}")))?;
        match key.as_ref() {
            b"TargetMode" => target_mode_external = value.eq_ignore_ascii_case("external"),
            b"Type" => type_value = value.into_owned(),
            b"Id" => id_value = value.into_owned(),
            _ => {}
        }
    }

    let type_lower = type_value.to_ascii_lowercase();
    let is_active_type = ACTIVE_TYPE_SUFFIXES
        .iter()
        .any(|suffix| type_lower.ends_with(suffix));
    let size = element.len();
    let id = if id_value.is_empty() {
        "?".to_owned()
    } else {
        id_value
    };

    if is_active_type {
        Ok(Some((
            ThreatClass::ActiveContent,
            format!("relationship {id} of active type '{type_value}'"),
            size,
        )))
    } else if target_mode_external {
        Ok(Some((
            ThreatClass::ExternalReference,
            format!("external relationship {id} -> '{type_value}'"),
            size,
        )))
    } else {
        Ok(None)
    }
}

fn skip_to_end(reader: &mut Reader<&[u8]>, name: &[u8], part: &str) -> Result<(), DomainError> {
    let mut depth = 1usize;
    loop {
        match reader
            .read_event()
            .map_err(|e| malformed(format!("malformed relationships XML in '{part}': {e}")))?
        {
            Event::Start(ref e) if e.local_name().as_ref() == name => depth += 1,
            Event::End(ref e) if e.local_name().as_ref() == name => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            Event::Eof => return Err(malformed(format!("unterminated element in '{part}'"))),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const ROOT_RELS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;

    const CONTENT_TYPES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;

    const DOCUMENT_XML: &[u8] = br#"<?xml version="1.0"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>PurgoVisibleBody</w:t></w:r></w:p></w:body>
</w:document>"#;

    fn write_part(zip: &mut ZipWriter<Cursor<Vec<u8>>>, name: &str, data: &[u8]) {
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file(name, opts).unwrap();
        zip.write_all(data).unwrap();
    }

    fn docx_with_macro() -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        write_part(&mut zip, "[Content_Types].xml", CONTENT_TYPES);
        write_part(&mut zip, "_rels/.rels", ROOT_RELS);
        write_part(&mut zip, "word/document.xml", DOCUMENT_XML);
        write_part(&mut zip, "word/vbaProject.bin", b"MACRO-EVIL-CODE");
        let doc_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject" Target="vbaProject.bin"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"#;
        write_part(&mut zip, "word/_rels/document.xml.rels", doc_rels);
        zip.finish().unwrap().into_inner()
    }

    fn docx_with_external_and_ole() -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        write_part(&mut zip, "[Content_Types].xml", CONTENT_TYPES);
        write_part(&mut zip, "_rels/.rels", ROOT_RELS);
        write_part(&mut zip, "word/document.xml", DOCUMENT_XML);
        write_part(
            &mut zip,
            "word/embeddings/oleObject1.bin",
            b"OLE-PACKAGED-EXE",
        );
        let doc_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://evil.example/x" TargetMode="External"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/oleObject1.bin"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.png"/>
</Relationships>"#;
        write_part(&mut zip, "word/_rels/document.xml.rels", doc_rels);
        zip.finish().unwrap().into_inner()
    }

    fn clean_docx() -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        write_part(&mut zip, "[Content_Types].xml", CONTENT_TYPES);
        write_part(&mut zip, "_rels/.rels", ROOT_RELS);
        write_part(&mut zip, "word/document.xml", DOCUMENT_XML);
        let doc_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"#;
        write_part(&mut zip, "word/_rels/document.xml.rels", doc_rels);
        zip.finish().unwrap().into_inner()
    }

    fn disarm(bytes: Vec<u8>) -> Result<DisarmOutput, DomainError> {
        OoxmlDisarmer::new().disarm(&Artifact::new(bytes), &Policy::strict())
    }

    fn part_names(bytes: &[u8]) -> Vec<String> {
        let mut archive = ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
        (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_owned())
            .collect()
    }

    fn read_part(bytes: &[u8], name: &str) -> Vec<u8> {
        let mut archive = ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
        let mut entry = archive.by_name(name).unwrap();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn drops_vba_project_but_keeps_the_document() {
        let out = disarm(docx_with_macro()).expect("valid docx disarms");
        let names = part_names(&out.bytes);

        assert!(
            !names.iter().any(|n| n.contains("vbaProject")),
            "vbaProject.bin must be gone, got {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "word/document.xml"),
            "document.xml must survive"
        );
        assert_eq!(read_part(&out.bytes, "word/document.xml"), DOCUMENT_XML);

        let rels = read_part(&out.bytes, "word/_rels/document.xml.rels");
        let rels = String::from_utf8(rels).unwrap();
        assert!(!rels.contains("vbaProject"), "vba relationship dropped");
        assert!(rels.contains("rId2"), "styles relationship kept");

        assert!(out.removed.iter().any(
            |r| r.class == ThreatClass::ActiveContent && r.location.contains("vbaProject.bin")
        ));
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent && r.detail.contains("active type")));
    }

    #[test]
    fn drops_external_links_and_ole_objects() {
        let out = disarm(docx_with_external_and_ole()).expect("valid docx disarms");
        let names = part_names(&out.bytes);

        assert!(
            !names.iter().any(|n| n.contains("oleObject")),
            "OLE object part removed, got {names:?}"
        );
        assert!(names.iter().any(|n| n == "word/document.xml"));

        let rels =
            String::from_utf8(read_part(&out.bytes, "word/_rels/document.xml.rels")).unwrap();
        assert!(!rels.contains("evil.example"), "external link dropped");
        assert!(!rels.contains("oleObject"), "ole relationship dropped");
        assert!(
            rels.contains("image1.png"),
            "benign image relationship kept"
        );

        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ExternalReference));
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent && r.location.contains("oleObject")));
    }

    #[test]
    fn leaves_a_clean_docx_useful_parts_intact() {
        let out = disarm(clean_docx()).expect("valid docx disarms");
        assert!(
            out.removed.is_empty(),
            "nothing to remove from a clean docx"
        );

        let mut names = part_names(&out.bytes);
        names.sort();
        assert_eq!(
            names,
            vec![
                "[Content_Types].xml".to_owned(),
                "_rels/.rels".to_owned(),
                "word/_rels/document.xml.rels".to_owned(),
                "word/document.xml".to_owned(),
            ]
        );
        assert_eq!(read_part(&out.bytes, "word/document.xml"), DOCUMENT_XML);
    }

    #[test]
    fn drops_xlsm_vba_project_by_name() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        write_part(&mut zip, "[Content_Types].xml", CONTENT_TYPES);
        write_part(&mut zip, "_rels/.rels", ROOT_RELS);
        write_part(&mut zip, "xl/workbook.xml", b"<workbook/>");
        write_part(&mut zip, "xl/vbaProject.bin", b"XLSM-MACRO-EVIL-CODE");
        let bytes = zip.finish().unwrap().into_inner();

        let out = disarm(bytes).expect("valid xlsm disarms");
        let names = part_names(&out.bytes);
        assert!(
            !names.iter().any(|n| n.contains("vbaProject")),
            "xl/vbaProject.bin must be gone, got {names:?}"
        );
        assert!(names.iter().any(|n| n == "xl/workbook.xml"));
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent
                && r.location.contains("xl/vbaProject.bin")));
    }

    #[test]
    fn drops_pptm_vba_project_and_embedded_ole_by_name() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        write_part(&mut zip, "[Content_Types].xml", CONTENT_TYPES);
        write_part(&mut zip, "_rels/.rels", ROOT_RELS);
        write_part(&mut zip, "ppt/presentation.xml", b"<presentation/>");
        write_part(&mut zip, "ppt/slides/slide1.xml", b"<sld>PPTM-SLIDE</sld>");
        write_part(&mut zip, "ppt/vbaProject.bin", b"PPTM-MACRO-EVIL-CODE");
        write_part(
            &mut zip,
            "ppt/embeddings/oleObject1.bin",
            b"PPTM-OLE-PACKAGED-EXE",
        );
        let bytes = zip.finish().unwrap().into_inner();

        let out = disarm(bytes).expect("valid pptm disarms");
        let names = part_names(&out.bytes);
        assert!(
            !names.iter().any(|n| n.contains("vbaProject")),
            "ppt/vbaProject.bin must be gone, got {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("oleObject")),
            "the embedded OLE object must be gone, got {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "ppt/slides/slide1.xml"),
            "the slide must survive"
        );
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent
                && r.location.contains("ppt/vbaProject.bin")));
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent && r.location.contains("oleObject")));
    }

    #[test]
    fn drops_macro_with_a_macro_enabled_content_type_but_no_rels_reference() {
        let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/ppt/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>"#;
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        write_part(&mut zip, "[Content_Types].xml", content_types);
        write_part(&mut zip, "_rels/.rels", ROOT_RELS);
        write_part(&mut zip, "ppt/presentation.xml", b"<presentation/>");
        write_part(&mut zip, "ppt/vbaProject.bin", b"UNREFERENCED-PPTM-MACRO");

        let pres_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>
</Relationships>"#;
        write_part(&mut zip, "ppt/_rels/presentation.xml.rels", pres_rels);
        let bytes = zip.finish().unwrap().into_inner();

        let out = disarm(bytes).expect("valid pptm disarms");
        let names = part_names(&out.bytes);
        assert!(
            !names.iter().any(|n| n.contains("vbaProject")),
            "an unreferenced ppt/vbaProject.bin must still be removed, got {names:?}"
        );
        assert!(
            out.removed
                .iter()
                .any(|r| r.class == ThreatClass::ActiveContent
                    && r.location.contains("ppt/vbaProject.bin")),
            "the removal must be recorded as active content"
        );

        let rels =
            String::from_utf8(read_part(&out.bytes, "ppt/_rels/presentation.xml.rels")).unwrap();
        assert!(rels.contains("rId1"), "the slide relationship is kept");
    }

    #[test]
    fn drops_vba_project_even_with_no_relationship_referencing_it() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        write_part(&mut zip, "[Content_Types].xml", CONTENT_TYPES);
        write_part(&mut zip, "_rels/.rels", ROOT_RELS);
        write_part(&mut zip, "word/document.xml", DOCUMENT_XML);
        write_part(&mut zip, "word/vbaProject.bin", b"UNREFERENCED-MACRO");

        let doc_rels = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"#;
        write_part(&mut zip, "word/_rels/document.xml.rels", doc_rels);
        let bytes = zip.finish().unwrap().into_inner();

        let out = disarm(bytes).expect("valid docx disarms");
        let names = part_names(&out.bytes);
        assert!(
            !names.iter().any(|n| n.contains("vbaProject")),
            "unreferenced vbaProject.bin must still be removed, got {names:?}"
        );
        assert!(
            out.removed
                .iter()
                .any(|r| r.class == ThreatClass::ActiveContent
                    && r.location.contains("vbaProject.bin")),
            "the removal must be recorded as active content"
        );

        let rels =
            String::from_utf8(read_part(&out.bytes, "word/_rels/document.xml.rels")).unwrap();
        assert!(rels.contains("rId1"), "styles relationship kept");
    }

    #[test]
    fn rejects_input_that_is_not_a_zip() {
        let err = disarm(b"PK not really a zip".to_vec()).unwrap_err();
        assert!(matches!(err, DomainError::MalformedInput { .. }));
    }

    #[test]
    fn rejects_empty_input_without_panicking() {
        let err = disarm(Vec::new()).unwrap_err();
        assert!(matches!(err, DomainError::MalformedInput { .. }));
    }

    #[test]
    fn rejects_malformed_rels_xml() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        write_part(&mut zip, "[Content_Types].xml", CONTENT_TYPES);
        write_part(
            &mut zip,
            "_rels/.rels",
            b"<Relationships><Relationship oops",
        );
        let bytes = zip.finish().unwrap().into_inner();
        let err = disarm(bytes).unwrap_err();
        assert!(matches!(err, DomainError::MalformedInput { .. }));
    }
}
