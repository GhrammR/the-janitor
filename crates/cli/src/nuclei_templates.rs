use anyhow::Context as _;
use common::slop::WebProofArtifact;
use serde::Serialize;

const JANITOR_CANARY: &str = "JANITOR_CANARY";

#[derive(Serialize)]
struct NucleiTemplate<'a> {
    id: String,
    info: TemplateInfo<'a>,
    http: Vec<HttpRequest<'a>>,
}

#[derive(Serialize)]
struct TemplateInfo<'a> {
    name: &'a str,
    author: &'a str,
    severity: &'a str,
    description: String,
    metadata: TemplateMetadata,
}

#[derive(Serialize)]
struct TemplateMetadata {
    janitor_target: String,
    janitor_source: String,
    janitor_sink: String,
    janitor_ifds: String,
    janitor_evidence_marker: String,
    janitor_template_hash: String,
}

#[derive(Serialize)]
struct HttpRequest<'a> {
    method: &'a str,
    path: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    headers: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    redirects: bool,
    max_redirects: u8,
    matchers_condition: &'a str,
    matchers: Vec<Matcher<'a>>,
}

#[derive(Serialize)]
struct Matcher<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    part: &'a str,
    words: Vec<&'a str>,
}

#[derive(Clone, Copy)]
enum SourceKind<'a> {
    UrlParam(&'a str),
    Header(&'a str),
    JsonBody(&'a str),
    Cookie(&'a str),
    RagChunk,
}

pub fn render_nuclei_template(artifact: &WebProofArtifact, target: &str) -> Option<String> {
    if artifact.source_label.trim().is_empty()
        || artifact.sink_label.trim().is_empty()
        || target.trim().is_empty()
    {
        return None;
    }

    let source = parse_source_kind(&artifact.source_label)?;
    let template_id = sanitize_id(&format!(
        "janitor-{}-{}-{}",
        artifact.source_label, artifact.sink_label, target
    ));
    let trace = artifact.ifds_trace_output();
    let evidence_marker = artifact.evidence_marker.clone().unwrap_or_default();
    let template_hash = blake3::hash(
        format!(
            "{}|{}|{}|{}|{}",
            target, artifact.source_label, artifact.sink_label, trace, evidence_marker
        )
        .as_bytes(),
    )
    .to_hex()
    .to_string();
    let request = build_http_request(source);
    let template = NucleiTemplate {
        id: template_id,
        info: TemplateInfo {
            name: "Janitor WebProofArtifact Canary Probe",
            author: "the-janitor",
            severity: "info",
            description: format!(
                "Non-destructive probe synthesized from {} -> {}.",
                artifact.source_label, artifact.sink_label
            ),
            metadata: TemplateMetadata {
                janitor_target: target.to_string(),
                janitor_source: artifact.source_label.clone(),
                janitor_sink: artifact.sink_label.clone(),
                janitor_ifds: trace,
                janitor_evidence_marker: evidence_marker,
                janitor_template_hash: template_hash,
            },
        },
        http: vec![request],
    };

    serde_yaml::to_string(&template)
        .context("serialize nuclei template")
        .ok()
}

fn parse_source_kind(source_label: &str) -> Option<SourceKind<'_>> {
    let (kind, name) = source_label.split_once(':')?;
    let name = name.trim();
    match kind.trim() {
        "url_param" if !name.is_empty() => Some(SourceKind::UrlParam(name)),
        "header" if !name.is_empty() => Some(SourceKind::Header(name)),
        "json_body" if !name.is_empty() => Some(SourceKind::JsonBody(name)),
        "cookie" if !name.is_empty() => Some(SourceKind::Cookie(name)),
        "rag_chunk" => Some(SourceKind::RagChunk),
        _ => None,
    }
}

fn build_http_request(source: SourceKind<'_>) -> HttpRequest<'static> {
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "Accept".to_string(),
        "text/html,application/json".to_string(),
    );

    let (method, path, body) = match source {
        SourceKind::UrlParam(name) => (
            "GET",
            vec![format!("{{{{BaseURL}}}}/?{name}={JANITOR_CANARY}")],
            None,
        ),
        SourceKind::Header(name) => {
            headers.insert(name.to_string(), JANITOR_CANARY.to_string());
            ("GET", vec!["{{BaseURL}}/".to_string()], None)
        }
        SourceKind::JsonBody(name) => {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            (
                "POST",
                vec!["{{BaseURL}}/".to_string()],
                Some(format!("{{\"{name}\":\"{JANITOR_CANARY}\"}}")),
            )
        }
        SourceKind::Cookie(name) => {
            headers.insert("Cookie".to_string(), format!("{name}={JANITOR_CANARY}"));
            ("GET", vec!["{{BaseURL}}/".to_string()], None)
        }
        SourceKind::RagChunk => {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            (
                "POST",
                vec!["{{BaseURL}}/".to_string()],
                Some(format!(
                    "{{\"query\":\"{JANITOR_CANARY}\",\"messages\":[{{\"role\":\"user\",\"content\":\"{JANITOR_CANARY}\"}}]}}"
                )),
            )
        }
    };

    HttpRequest {
        method,
        path,
        headers,
        body,
        redirects: true,
        max_redirects: 2,
        matchers_condition: "and",
        matchers: vec![Matcher {
            kind: "word",
            part: "body",
            words: vec![JANITOR_CANARY],
        }],
    }
}

fn sanitize_id(value: &str) -> String {
    let mut id = String::with_capacity(value.len());
    let mut last_dash = false;
    for ch in value.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            last_dash = false;
            ch.to_ascii_lowercase()
        } else if last_dash {
            continue;
        } else {
            last_dash = true;
            '-'
        };
        id.push(normalized);
    }
    id.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::slop::ProofClass;

    #[test]
    fn render_nuclei_template_outputs_valid_yaml_for_dom_xss_artifact() {
        let artifact = WebProofArtifact {
            source_label: "url_param:returnTo".to_string(),
            sink_label: "sink:innerHTML".to_string(),
            ifds_trace: vec!["handler".to_string(), "render".to_string()],
            evidence_marker: Some("dom_canary:reflected".to_string()),
            proof_class: ProofClass::ReachabilityProof,
        };

        let rendered = render_nuclei_template(&artifact, "github.com/acme/web")
            .expect("dom xss artifact should synthesize nuclei template");
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&rendered).expect("rendered template must be valid yaml");

        assert_eq!(
            parsed["info"]["metadata"]["janitor_source"],
            "url_param:returnTo"
        );
        assert_eq!(parsed["http"][0]["method"], "GET");
        assert!(rendered.contains("JANITOR_CANARY"));
    }
}
