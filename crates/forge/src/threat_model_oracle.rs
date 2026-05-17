//! Sprint 140 — Threat Model Oracle.
//!
//! Pre-detector module that runs BEFORE `security:missing_ownership_check`
//! and `security:idor` findings are emitted by the hunt pipeline. Inspects
//! the target's authentication and authorization surface and decides
//! whether a candidate finding should be suppressed (covered by a
//! framework-level guard the upstream detector missed), downgraded to
//! informational (covered by a blueprint-level auth hook that exists but
//! is harder to attribute), or emitted as-is.
//!
//! Motivating regression (Sprint 140): the SecureDrop IDOR CANDIDATE
//! (44% approval, $1000-$1500 P2) was promoted by the upstream
//! `missing_ownership_check` detector for two sprints. A 20-minute Tier-1
//! validation in Sprint 140 proved it was a false positive — every cited
//! route was either decorated with `@admin_required` or covered by a
//! blueprint-level `@app.before_request` login hook. The detector
//! emitted the pattern because it lacked auth-context awareness; this
//! oracle is the structural cure.
//!
//! ## Decision Tree
//!
//! 1. **Per-route decorator scan**: examine the cited file within a
//!    `DECORATOR_WINDOW` of lines above the finding's line. If any
//!    framework auth decorator is present → `Suppress`.
//! 2. **Framework app-entry scan**: parse `__init__.py` / `app.py` /
//!    `main.py` / `server.py` within 2 directory levels above the cited
//!    file for blueprint-level auth hooks (Flask `@app.before_request`,
//!    Django `AuthenticationMiddleware`, FastAPI router `dependencies=`,
//!    Rails controller `before_action`). If covered →
//!    `DowngradeInformational`.
//! 3. **Threat-model marker scan**: scan `THREAT_MODEL.md`, `SECURITY.md`,
//!    `docs/threat_model/*.md`, `README.md` (first 4 KiB each) for
//!    shared-access keywords. If matched AND the finding class is
//!    ownership/IDOR → `Suppress`.
//! 4. **Default**: `Emit` — preserve upstream detector behavior.
//!
//! The oracle is class-scoped: the suppression rules apply only to
//! ownership/IDOR-class findings. A finding with `id: "security:sql_injection"`
//! is unaffected even when a shared-access threat model is detected.

use std::path::Path;

use common::slop::StructuredFinding;

/// Lines above a finding's cited line to search for decorators.
///
/// A typical Python decorator stack on a Flask/Django route handler sits
/// within 10 lines of the `def` line. 20 lines gives headroom for
/// docstrings and parameter wrapping.
const DECORATOR_WINDOW: usize = 20;

/// Maximum bytes of any markdown threat-model document to scan.
///
/// Modern READMEs / THREAT_MODEL files run 8-32 KiB. The 4 KiB window
/// captures the introductory threat-model section without paying the cost
/// of full-document scans on every finding.
const THREAT_MODEL_SCAN_BYTES: usize = 4 * 1024;

/// Per-route auth decorators recognised in Python/Ruby. Match is a simple
/// substring check inside the decorator window so the same constant
/// covers Flask, Django, and FastAPI patterns simultaneously.
const PER_ROUTE_DECORATORS: &[&str] = &[
    "@login_required",
    "@admin_required",
    "@auth_required",
    "@permission_required",
    "@user_passes_test",
    "Depends(get_current_user",
    "Depends(get_current_admin",
    "Security(",
    "before_action :require_login",
    "before_action :require_admin",
    "before_action :authenticate",
];

/// Framework-level auth hook keywords. Presence in `__init__.py`,
/// `app.py`, `main.py`, or `server.py` near the cited file indicates the
/// blueprint requires authentication globally.
const FRAMEWORK_AUTH_HOOKS: &[&str] = &[
    "@app.before_request",
    "session.logged_in()",
    "current_user.is_authenticated",
    "AuthenticationMiddleware",
    "app.middleware('http')",
    "APIRouter(dependencies=",
    "ApplicationController",
];

/// Shared-access threat-model markers. When any of these phrases appears
/// in a project's threat-model documentation, the project explicitly
/// declares that all authenticated principals have equivalent access —
/// per-resource ownership checks are not part of the security model.
const SHARED_ACCESS_MARKERS: &[&str] = &[
    "shared access",
    "peer access",
    "collaborative model",
    "flat authorization",
    "all authenticated users have equal",
    "all journalists have access",
    "all members can",
    "no per-resource ownership",
    "flat permission model",
];

/// Finding-class substrings that indicate an ownership / IDOR-class
/// pattern. The Step-3 threat-model suppression is scoped to these
/// classes only — a SQL injection finding is never suppressed by the
/// presence of a shared-access threat model.
const OWNERSHIP_CLASS_NEEDLES: &[&str] = &[
    "missing_ownership_check",
    "idor",
    "ownership",
    "horizontal_priv",
    "broken_object_level",
];

/// Verdict returned by the threat-model oracle. The hunt post-filter
/// chain interprets these as: remove from results (Suppress), set
/// `severity = Informational` and annotate (DowngradeInformational), or
/// no-op (Emit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatModelVerdict {
    /// Drop the finding from the output — the cited code is protected by
    /// a per-route or framework-level guard the upstream detector failed
    /// to account for.
    Suppress,
    /// Keep the finding in the output but at `Informational` severity. The
    /// blueprint covers the route but the attribution is too coarse to
    /// suppress outright (e.g. Django middleware applies to most routes
    /// but `@csrf_exempt` can override).
    DowngradeInformational,
    /// Preserve the upstream detector verdict — no auth gate is detectable
    /// at this site.
    Emit,
}

/// Classify a single finding against the target's auth surface.
///
/// `dir` is the scan root passed to `janitor hunt`; `finding` is a
/// candidate emitted by an upstream detector. Returns one of the three
/// `ThreatModelVerdict` variants.
pub fn classify_finding(dir: &Path, finding: &StructuredFinding) -> ThreatModelVerdict {
    let Some(rel_path) = finding.file.as_deref() else {
        return ThreatModelVerdict::Emit;
    };
    let abs_path = dir.join(rel_path);

    if scan_per_route_decorators(&abs_path, finding.line) {
        return ThreatModelVerdict::Suppress;
    }
    if scan_framework_auth_hooks(dir, &abs_path) {
        return ThreatModelVerdict::DowngradeInformational;
    }
    if is_ownership_class(&finding.id) && scan_threat_model_markers(dir) {
        return ThreatModelVerdict::Suppress;
    }
    ThreatModelVerdict::Emit
}

fn is_ownership_class(finding_id: &str) -> bool {
    let lower = finding_id.to_lowercase();
    OWNERSHIP_CLASS_NEEDLES
        .iter()
        .any(|needle| lower.contains(needle))
}

fn scan_per_route_decorators(file_path: &Path, finding_line: Option<u32>) -> bool {
    let Ok(content) = std::fs::read_to_string(file_path) else {
        return false;
    };
    let lines: Vec<&str> = content.lines().collect();
    let target_idx = finding_line
        .map(|l| (l as usize).saturating_sub(1))
        .unwrap_or(0);
    let start = target_idx.saturating_sub(DECORATOR_WINDOW);
    // Include the cited line itself so FastAPI `Depends(...)` in the
    // function signature (on the same line as `def`) is detected, not
    // just decorator stacks above the function.
    let end = (target_idx + 1).min(lines.len());
    for line in &lines[start..end.max(start)] {
        let trimmed = line.trim_start();
        for decorator in PER_ROUTE_DECORATORS {
            if trimmed.contains(decorator) {
                return true;
            }
        }
    }
    false
}

fn scan_framework_auth_hooks(scan_root: &Path, cited_file: &Path) -> bool {
    // `settings.py` covers Django (MIDDLEWARE list lives there); the
    // others cover Flask / FastAPI / generic Python web frameworks.
    let candidate_files = [
        "__init__.py",
        "app.py",
        "main.py",
        "server.py",
        "settings.py",
    ];
    let cited_parent = cited_file.parent();

    let mut search_dirs: Vec<&Path> = Vec::new();
    if let Some(parent) = cited_parent {
        search_dirs.push(parent);
        if let Some(grandparent) = parent.parent() {
            if grandparent.starts_with(scan_root) || grandparent == scan_root {
                search_dirs.push(grandparent);
            }
        }
    }
    search_dirs.push(scan_root);

    for dir in search_dirs {
        for filename in &candidate_files {
            let path = dir.join(filename);
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for hook in FRAMEWORK_AUTH_HOOKS {
                if content.contains(hook) {
                    return true;
                }
            }
        }
    }
    false
}

fn scan_threat_model_markers(scan_root: &Path) -> bool {
    let candidates = [
        scan_root.join("THREAT_MODEL.md"),
        scan_root.join("SECURITY.md"),
        scan_root.join("README.md"),
        scan_root.join("docs").join("threat_model.md"),
        scan_root.join("docs").join("THREAT_MODEL.md"),
        scan_root
            .join("docs")
            .join("threat_model")
            .join("threat_model.md"),
    ];
    for path in &candidates {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let window_end = content.len().min(THREAT_MODEL_SCAN_BYTES);
        let Some(window) = content.get(..window_end) else {
            continue;
        };
        let lower = window.to_lowercase();
        for marker in SHARED_ACCESS_MARKERS {
            if lower.contains(marker) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::slop::StructuredFinding;
    use std::fs;
    use tempfile::TempDir;

    fn finding(id: &str, file: &str, line: u32) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            file: Some(file.to_string()),
            line: Some(line),
            ..Default::default()
        }
    }

    #[test]
    fn flask_admin_required_suppresses() {
        let dir = TempDir::new().unwrap();
        let app_dir = dir.path().join("journalist_app");
        fs::create_dir_all(&app_dir).unwrap();
        fs::write(
            app_dir.join("admin.py"),
            b"from flask import Blueprint\n\nview = Blueprint('admin', __name__)\n\n@view.route('/edit/<int:user_id>', methods=('GET', 'POST'))\n@admin_required\ndef edit_user(user_id):\n    return 'ok'\n",
        )
        .unwrap();
        let f = finding(
            "security:missing_ownership_check",
            "journalist_app/admin.py",
            7,
        );
        assert_eq!(
            classify_finding(dir.path(), &f),
            ThreatModelVerdict::Suppress
        );
    }

    #[test]
    fn flask_before_request_login_downgrades() {
        let dir = TempDir::new().unwrap();
        let app_dir = dir.path().join("journalist_app");
        fs::create_dir_all(&app_dir).unwrap();
        fs::write(
            app_dir.join("__init__.py"),
            b"from flask import Flask\n\napp = Flask(__name__)\n\n@app.before_request\ndef require_login():\n    if not session.logged_in():\n        abort(403)\n",
        )
        .unwrap();
        fs::write(
            app_dir.join("main.py"),
            b"from journalist_app import view\n\n@view.route('/download_unread/<filesystem_id>')\ndef download_unread(filesystem_id):\n    return 'ok'\n",
        )
        .unwrap();
        let f = finding(
            "security:missing_ownership_check",
            "journalist_app/main.py",
            4,
        );
        assert_eq!(
            classify_finding(dir.path(), &f),
            ThreatModelVerdict::DowngradeInformational
        );
    }

    #[test]
    fn securedrop_threat_model_suppresses_ownership() {
        let dir = TempDir::new().unwrap();
        let docs_dir = dir.path().join("docs");
        fs::create_dir_all(&docs_dir).unwrap();
        fs::write(
            docs_dir.join("threat_model.md"),
            b"# SecureDrop Threat Model\n\nAll journalists have access to all sources. This is by design - sources are anonymous and journalists collaboratively respond to leaks.\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("bare_route.py"),
            b"def download_single(filesystem_id, fn):\n    return open(fn).read()\n",
        )
        .unwrap();
        let f = finding("security:missing_ownership_check", "bare_route.py", 1);
        assert_eq!(
            classify_finding(dir.path(), &f),
            ThreatModelVerdict::Suppress
        );
    }

    #[test]
    fn django_middleware_downgrades() {
        let dir = TempDir::new().unwrap();
        let project_dir = dir.path().join("project");
        fs::create_dir_all(&project_dir).unwrap();
        fs::write(
            project_dir.join("settings.py"),
            b"MIDDLEWARE = [\n    'django.contrib.sessions.middleware.SessionMiddleware',\n    'django.contrib.auth.middleware.AuthenticationMiddleware',\n]\n",
        )
        .unwrap();
        let views_dir = project_dir.join("views");
        fs::create_dir_all(&views_dir).unwrap();
        fs::write(
            views_dir.join("__init__.py"),
            b"from project.settings import MIDDLEWARE\n",
        )
        .unwrap();
        fs::write(
            views_dir.join("api.py"),
            b"def fetch_record(request, record_id):\n    return Record.objects.get(pk=record_id)\n",
        )
        .unwrap();
        let f = finding("security:idor", "project/views/api.py", 1);
        assert_eq!(
            classify_finding(dir.path(), &f),
            ThreatModelVerdict::DowngradeInformational
        );
    }

    #[test]
    fn fastapi_depends_suppresses() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("api.py"),
            b"from fastapi import FastAPI, Depends\n\napp = FastAPI()\n\n@app.get('/items/{item_id}')\nasync def read_item(item_id: int, user = Depends(get_current_user)):\n    return Item.get(item_id)\n",
        )
        .unwrap();
        let f = finding("security:missing_ownership_check", "api.py", 6);
        assert_eq!(
            classify_finding(dir.path(), &f),
            ThreatModelVerdict::Suppress
        );
    }

    #[test]
    fn rails_before_action_suppresses() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("orders_controller.rb"),
            b"class OrdersController < ApplicationController\n  before_action :require_login\n\n  def show\n    @order = Order.find(params[:id])\n  end\nend\n",
        )
        .unwrap();
        let f = finding("security:idor", "orders_controller.rb", 5);
        assert_eq!(
            classify_finding(dir.path(), &f),
            ThreatModelVerdict::Suppress
        );
    }

    #[test]
    fn no_guards_emits() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("bare.py"),
            b"def fetch_record(record_id):\n    return Record.objects.get(pk=record_id)\n",
        )
        .unwrap();
        let f = finding("security:missing_ownership_check", "bare.py", 1);
        assert_eq!(classify_finding(dir.path(), &f), ThreatModelVerdict::Emit);
    }

    #[test]
    fn non_ownership_class_unaffected_by_threat_model() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("THREAT_MODEL.md"),
            b"# Threat Model\n\nAll authenticated users have equal access to all resources.\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("query.py"),
            b"def search(term):\n    cursor.execute(f\"SELECT * FROM logs WHERE msg LIKE '{term}'\")\n",
        )
        .unwrap();
        let f = finding("security:sql_injection", "query.py", 2);
        // SQL injection MUST NOT be suppressed by a shared-access threat model.
        assert_eq!(classify_finding(dir.path(), &f), ThreatModelVerdict::Emit);
    }
}
