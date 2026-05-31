use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

use lopdf::{Document, Object, ObjectId};
use purgo_domain::{
    Artifact, DisarmOutput, Disarmer, DomainError, FileFormat, Policy, RemovedItem, ThreatClass,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct PdfDisarmer;

impl PdfDisarmer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

fn malformed(reason: impl Into<String>) -> DomainError {
    DomainError::MalformedInput {
        format: FileFormat::Pdf,
        reason: reason.into(),
    }
}

const ACTIVE_CONTENT_KEYS: &[&[u8]] = &[b"OpenAction", b"AA", b"JavaScript", b"JS"];

const EMBEDDED_FILE_KEYS: &[&[u8]] = &[b"EmbeddedFiles", b"EF"];

const ACTION_HOLDER_KEYS: &[&[u8]] = &[b"A", b"Next"];

const DANGEROUS_ACTION_SUBTYPES: &[&[u8]] = &[
    b"Launch",
    b"JavaScript",
    b"GoToR",
    b"URI",
    b"SubmitForm",
    b"ImportData",
    b"Rendition",
];

const MAX_DEPTH: u32 = 64;

impl Disarmer for PdfDisarmer {
    fn format(&self) -> FileFormat {
        FileFormat::Pdf
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
    let mut doc = Document::load_mem(data).map_err(|e| malformed(format!("cannot parse: {e}")))?;

    let mut removed: Vec<RemovedItem> = Vec::new();

    let dangerous_actions: BTreeSet<ObjectId> = doc
        .objects
        .iter()
        .filter(|(_, obj)| is_dangerous_action_object(obj))
        .map(|(id, _)| *id)
        .collect();

    let mut trailer = std::mem::replace(&mut doc.trailer, lopdf::Dictionary::new());
    sanitize_dictionary(&mut trailer, "trailer", 0, &dangerous_actions, &mut removed)?;
    doc.trailer = trailer;

    let ids: Vec<ObjectId> = doc.objects.keys().copied().collect();
    for id in ids {
        if let Some(object) = doc.objects.get_mut(&id) {
            let location = format!("object {}_{}", id.0, id.1);
            sanitize_object(object, &location, 0, &dangerous_actions, &mut removed)?;
        }
    }

    let payload_ids: Vec<ObjectId> = doc
        .objects
        .iter()
        .filter(|(id, obj)| dangerous_actions.contains(id) || is_embedded_file_object(obj))
        .map(|(id, _)| *id)
        .collect();
    for id in payload_ids {
        if let Some(obj) = doc.objects.remove(&id) {
            let (class, detail) = if dangerous_actions.contains(&id) {
                (
                    ThreatClass::ActiveContent,
                    "dangerous action object (/S launch/javascript/uri/…)",
                )
            } else {
                (
                    ThreatClass::EmbeddedFile,
                    "embedded file payload (/EmbeddedFile or /Filespec)",
                )
            };
            removed.push(RemovedItem::new(
                format!("object {}_{}", id.0, id.1),
                class,
                detail,
                object_size(&obj),
            ));
        }
    }

    doc.prune_objects();

    let mut out: Vec<u8> = Vec::new();
    doc.save_to(&mut out)
        .map_err(|e| malformed(format!("cannot re-serialise: {e}")))?;

    Ok(DisarmOutput::new(out, removed))
}

fn sanitize_object(
    object: &mut Object,
    location: &str,
    depth: u32,
    dangerous_actions: &BTreeSet<ObjectId>,
    removed: &mut Vec<RemovedItem>,
) -> Result<(), DomainError> {
    if depth >= MAX_DEPTH {
        return Err(malformed("PDF object nesting too deep"));
    }
    match object {
        Object::Dictionary(dict) => {
            sanitize_dictionary(dict, location, depth, dangerous_actions, removed)
        }
        Object::Stream(stream) => sanitize_dictionary(
            &mut stream.dict,
            location,
            depth,
            dangerous_actions,
            removed,
        ),
        Object::Array(array) => {
            for item in array.iter_mut() {
                sanitize_object(item, location, depth + 1, dangerous_actions, removed)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn sanitize_dictionary(
    dict: &mut lopdf::Dictionary,
    location: &str,
    depth: u32,
    dangerous_actions: &BTreeSet<ObjectId>,
    removed: &mut Vec<RemovedItem>,
) -> Result<(), DomainError> {
    if depth >= MAX_DEPTH {
        return Err(malformed("PDF object nesting too deep"));
    }

    let mut to_remove: Vec<(Vec<u8>, ThreatClass, String)> = Vec::new();
    for (key, value) in dict.iter() {
        if let Some(class) = classify_key(key, value, dangerous_actions) {
            let name = String::from_utf8_lossy(key).into_owned();
            let detail = match class {
                ThreatClass::EmbeddedFile => format!("embedded-file reference /{name}"),
                _ => format!("active-content entry /{name}"),
            };
            to_remove.push((key.clone(), class, detail));
        }
    }

    for (key, class, detail) in to_remove {
        if let Some(value) = dict.remove(&key) {
            let name = String::from_utf8_lossy(&key).into_owned();
            removed.push(RemovedItem::new(
                format!("{location} /{name}"),
                class,
                detail,
                object_size(&value),
            ));
        }
    }

    for (_, value) in dict.iter_mut() {
        sanitize_object(value, location, depth + 1, dangerous_actions, removed)?;
    }
    Ok(())
}

fn classify_key(
    key: &[u8],
    value: &Object,
    dangerous_actions: &BTreeSet<ObjectId>,
) -> Option<ThreatClass> {
    if ACTIVE_CONTENT_KEYS.contains(&key) {
        return Some(ThreatClass::ActiveContent);
    }
    if EMBEDDED_FILE_KEYS.contains(&key) {
        return Some(ThreatClass::EmbeddedFile);
    }
    if ACTION_HOLDER_KEYS.contains(&key) && is_dangerous_action_holder(value, dangerous_actions) {
        return Some(ThreatClass::ActiveContent);
    }
    None
}

fn is_dangerous_action_holder(value: &Object, dangerous_actions: &BTreeSet<ObjectId>) -> bool {
    match value {
        Object::Reference(id) => dangerous_actions.contains(id),
        Object::Dictionary(dict) => is_dangerous_action_subtype(dict),
        _ => false,
    }
}

fn is_dangerous_action_object(object: &Object) -> bool {
    match object {
        Object::Dictionary(dict) => is_dangerous_action_subtype(dict),
        Object::Stream(stream) => is_dangerous_action_subtype(&stream.dict),
        _ => false,
    }
}

fn is_dangerous_action_subtype(dict: &lopdf::Dictionary) -> bool {
    match dict.get(b"S").and_then(Object::as_name) {
        Ok(subtype) => DANGEROUS_ACTION_SUBTYPES.contains(&subtype),
        Err(_) => false,
    }
}

fn is_embedded_file_object(object: &Object) -> bool {
    let type_name = match object {
        Object::Stream(stream) => stream.dict.get(b"Type").and_then(Object::as_name).ok(),
        Object::Dictionary(dict) => dict.get(b"Type").and_then(Object::as_name).ok(),
        _ => None,
    };
    matches!(type_name, Some(b"EmbeddedFile") | Some(b"Filespec"))
}

fn object_size(object: &Object) -> usize {
    match object {
        Object::Stream(stream) => stream.content.len(),
        Object::String(bytes, _) | Object::Name(bytes) => bytes.len(),
        Object::Array(array) => array.iter().map(object_size).sum(),
        Object::Dictionary(dict) => dict
            .iter()
            .map(|(k, v)| k.len() + object_size(v))
            .sum::<usize>(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{dictionary, Dictionary, Stream};

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn armed_pdf() -> Vec<u8> {
        let mut doc = Document::with_version("1.5");

        let content_id = doc.add_object(Stream::new(
            dictionary! {},
            b"BT /F1 12 Tf (PurgoVisibleText) Tj ET".to_vec(),
        ));

        let pages_id = doc.new_object_id();

        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,

            "AA" => dictionary! { "O" => dictionary! { "S" => "JavaScript", "JS" => "app.alert(1);" } },
        });

        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            }),
        );

        let js_action_id = doc.add_object(dictionary! {
            "Type" => "Action",
            "S" => "JavaScript",
            "JS" => "this.exportDataObject({cName:'evil'});",
        });

        let ef_stream_id = doc.add_object(Stream::new(
            dictionary! { "Type" => "EmbeddedFile" },
            b"MALICIOUS-PAYLOAD-BYTES".to_vec(),
        ));
        let filespec_id = doc.add_object(dictionary! {
            "Type" => "Filespec",
            "F" => Object::string_literal("evil.exe"),
            "EF" => dictionary! { "F" => ef_stream_id },
        });

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
            "OpenAction" => js_action_id,
            "Names" => dictionary! {
                "JavaScript" => dictionary! {
                    "Names" => vec![
                        Object::string_literal("evil"),
                        js_action_id.into(),
                    ],
                },
                "EmbeddedFiles" => dictionary! {
                    "Names" => vec![
                        Object::string_literal("evil.exe"),
                        filespec_id.into(),
                    ],
                },
            },
        });

        doc.trailer.set("Root", catalog_id);

        let mut buf = Vec::new();
        doc.save_to(&mut buf).expect("sample pdf must serialise");
        buf
    }

    fn disarm(bytes: Vec<u8>) -> Result<DisarmOutput, DomainError> {
        PdfDisarmer::new().disarm(&Artifact::new(bytes), &Policy::strict())
    }

    #[test]
    fn neutralises_active_content_and_embedded_files_but_keeps_the_page() {
        let out = disarm(armed_pdf()).expect("valid pdf disarms");

        let reparsed = Document::load_mem(&out.bytes).expect("output is valid pdf");
        let pages = reparsed.get_pages();
        assert_eq!(pages.len(), 1, "the single page must survive");
        assert!(
            contains(&out.bytes, b"PurgoVisibleText"),
            "page text must be preserved"
        );

        assert!(!contains(&out.bytes, b"OpenAction"), "OpenAction removed");
        assert!(!contains(&out.bytes, b"/AA"), "additional actions removed");
        assert!(!contains(&out.bytes, b"app.alert"), "page JS removed");
        assert!(
            !contains(&out.bytes, b"exportDataObject"),
            "catalog JS action removed"
        );
        assert!(
            !contains(&out.bytes, b"MALICIOUS-PAYLOAD-BYTES"),
            "embedded file payload removed"
        );
        assert!(!contains(&out.bytes, b"EmbeddedFile"), "EmbeddedFile gone");

        let catalog = reparsed.catalog().expect("catalog present");
        assert!(!catalog.has(b"OpenAction"));
        let names_clean = catalog
            .get(b"Names")
            .ok()
            .and_then(|o| o.as_dict().ok())
            .map(|d| !d.has(b"JavaScript") && !d.has(b"EmbeddedFiles"))
            .unwrap_or(true);
        assert!(names_clean, "Names tree must carry no JS/EmbeddedFiles");

        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent));
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::EmbeddedFile));
    }

    #[test]
    fn drops_launch_action_on_an_annotation() {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,

            "Annots" => vec![Object::Dictionary(dictionary! {
                "Type" => "Annot",
                "Subtype" => "Link",
                "A" => dictionary! { "S" => "Launch", "F" => Object::string_literal("calc.exe") },
            })],
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        let out = disarm(buf).expect("valid pdf disarms");
        assert!(!contains(&out.bytes, b"Launch"), "launch action removed");
        assert!(!contains(&out.bytes, b"calc.exe"), "launch target removed");
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent && r.location.contains("/A")));
    }

    #[test]
    fn drops_launch_action_referenced_by_an_indirect_object() {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let launch_id = doc.add_object(dictionary! {
            "Type" => "Action",
            "S" => "Launch",
            "F" => Object::string_literal("calc.exe"),
        });
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Annots" => vec![Object::Dictionary(dictionary! {
                "Type" => "Annot",
                "Subtype" => "Link",

                "A" => launch_id,
            })],
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        let out = disarm(buf).expect("valid pdf disarms");
        assert!(
            !contains(&out.bytes, b"Launch"),
            "the Launch sub-type byte must not survive in the output"
        );
        assert!(
            !contains(&out.bytes, b"calc.exe"),
            "the launch target must not survive in the output"
        );
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent));
    }

    #[test]
    fn drops_gotor_action_referenced_by_an_indirect_object() {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let gotor_id = doc.add_object(dictionary! {
            "Type" => "Action",
            "S" => "GoToR",
            "F" => Object::string_literal("\\\\attacker\\share\\evil.pdf"),
        });
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "AA" => dictionary! { "O" => gotor_id },
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        let out = disarm(buf).expect("valid pdf disarms");

        assert!(!contains(&out.bytes, b"GoToR"), "GoToR sub-type removed");
        assert!(!contains(&out.bytes, b"attacker"), "remote target removed");
    }

    #[test]
    fn rejects_inline_nesting_deeper_than_max_depth_fail_closed() {
        let mut nested = Object::Dictionary(dictionary! { "OpenAction" => "x" });
        for _ in 0..(MAX_DEPTH + 5) {
            nested = Object::Array(vec![nested]);
        }
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Deep" => nested,
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        let err = disarm(buf).unwrap_err();
        assert!(
            matches!(err, DomainError::MalformedInput { .. }),
            "deep inline nesting must fail closed, got {err:?}"
        );
    }

    #[test]
    fn strips_a_dangerous_key_buried_just_within_max_depth() {
        let mut nested = Object::Dictionary(dictionary! {
            "OpenAction" => dictionary! { "S" => "JavaScript", "JS" => "app.alert('deep');" },
        });
        for _ in 0..(MAX_DEPTH / 2) {
            nested = Object::Array(vec![nested]);
        }
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Deep" => nested,
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        let out = disarm(buf).expect("nesting within the bound disarms, not rejects");
        assert!(
            !contains(&out.bytes, b"OpenAction"),
            "the deeply-but-legally nested OpenAction must be stripped"
        );
        assert!(
            !contains(&out.bytes, b"app.alert"),
            "its JavaScript payload must be stripped too"
        );
        assert!(out
            .removed
            .iter()
            .any(|r| r.class == ThreatClass::ActiveContent));
    }

    #[test]
    fn keeps_a_clean_pdf_intact() {
        let mut doc = Document::with_version("1.5");
        let content_id = doc.add_object(Stream::new(
            Dictionary::new(),
            b"BT /F1 12 Tf (Hello) Tj ET".to_vec(),
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
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();

        let out = disarm(buf).expect("valid pdf disarms");
        assert!(out.removed.is_empty(), "nothing to remove from a clean pdf");
        assert!(contains(&out.bytes, b"Hello"));
        assert_eq!(Document::load_mem(&out.bytes).unwrap().get_pages().len(), 1);
    }

    #[test]
    fn rejects_input_that_is_not_a_pdf() {
        let err = disarm(b"%PDF-1.7\nthis is not really a pdf".to_vec()).unwrap_err();
        assert!(matches!(err, DomainError::MalformedInput { .. }));
    }

    #[test]
    fn rejects_empty_input_without_panicking() {
        let err = disarm(Vec::new()).unwrap_err();
        assert!(matches!(err, DomainError::MalformedInput { .. }));
    }
}
