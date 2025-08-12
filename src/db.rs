use std::{
    collections::HashSet,
    error::Error,
    sync::{Arc, Mutex},
};

use rusqlite::{params, Connection};

use crate::osv;

/// Extract git commit URLs
/// Looks for patterns like:
/// - /commits/[hash]
/// - /commit/[hash]  
/// - github.com/.../commit/[hash]
/// Note: Excludes URLs that contain "/pull/" to avoid confusion with PR URLs
fn extract_git_commits(url: &str) -> Option<Vec<String>> {
    let mut commits = Vec::new();
    
    // Skip URLs that contain "/pull/" as they are pull request URLs
    if url.contains("/pull/") {
        return None;
    }
    
    // Pattern for commit URLs: /commit/hash or /commits/hash
    if let Some(commit_start) = url.find("/commit") {
        let after_commit = &url[commit_start..];
        // Handle both /commit/ and /commits/ patterns
        let hash_start = if after_commit.starts_with("/commits/") {
            9  // Skip "/commits/"
        } else if after_commit.starts_with("/commit/") {
            8  // Skip "/commit/"
        } else {
            return None;
        };
        
        let hash_part = &after_commit[hash_start..];
        // Extract the hash (typically 40 chars for full SHA, but could be shorter)
        // Look for the next non-hex character or end of string
        let mut end = 0;
        for (i, c) in hash_part.char_indices() {
            if c.is_ascii_hexdigit() {
                end = i + 1;
            } else {
                break;
            }
        }
        if end >= 7 && end <= 40 {  // Valid git hash length range
            // Return the full URL instead of just the hash
            commits.push(url.to_string());
        }
    }
    
    if commits.is_empty() {
        None
    } else {
        Some(commits)
    }
}

/// Extract pull request URLs
/// Looks for patterns like:
/// - /pull/[number]
/// - /pulls/[number]
/// - github.com/.../pull/[number]
fn extract_pull_requests(url: &str) -> Option<Vec<String>> {
    let mut pull_requests = Vec::new();
    
    // Pattern for pull request URLs: /pull/number or /pulls/number
    if let Some(pull_start) = url.find("/pull") {
        let after_pull = &url[pull_start..];
        // Handle both /pull/ and /pulls/ patterns
        let number_start = if after_pull.starts_with("/pulls/") {
            7  // Skip "/pulls/"
        } else if after_pull.starts_with("/pull/") {
            6  // Skip "/pull/"
        } else {
            return None;
        };
        
        let number_part = &after_pull[number_start..];
        // Extract the PR number (digits only)
        let mut end = 0;
        for (i, c) in number_part.char_indices() {
            if c.is_ascii_digit() {
                end = i + 1;
            } else {
                break;
            }
        }
        if end > 0 {  // Valid PR number
            // For pull request URLs, we want to extract just the base PR URL
            // without any additional paths like /commits/hash
            let base_url = if let Some(commits_pos) = url.find("/commits/") {
                &url[..commits_pos]
            } else if let Some(files_pos) = url.find("/files") {
                &url[..files_pos]
            } else {
                url
            };
            pull_requests.push(base_url.to_string());
        }
    }
    
    if pull_requests.is_empty() {
        None
    } else {
        Some(pull_requests)
    }
}

pub struct DB {
    locked_conn: Arc<Mutex<Connection>>,
}

const CREATE_ADVISORIES_TABLE: &str = r#"
CREATE TABLE advisories (
    ghsa TEXT PRIMARY KEY,
    schema_version TEXT,
    modified TEXT NOT NULL,
    published TEXT,
    withdrawn TEXT,
    cve TEXT,
    ecosystems TEXT,
    summary TEXT,
    details TEXT,
    severity TEXT,
    cwes TEXT,
    github_reviewed INTEGER,
    github_reviewed_at TEXT,
    nvd_published_at TEXT,
    ref_commits TEXT,
    ref_pull_requests TEXT
)"#;

const CREATE_AFFECTED_PACKAGES_TABLE: &str = r#"
CREATE TABLE affected_packages (
    ghsa TEXT,
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    ranges TEXT,
    versions TEXT
)"#;

const INSERT_ADVISORY: &str = r#"
INSERT INTO advisories (
     ghsa,  schema_version,  modified,  published,  withdrawn,  cve,  ecosystems,  summary,
     details,  severity,  cwes,  github_reviewed,  github_reviewed_at,  nvd_published_at,  ref_commits,  ref_pull_requests
) VALUES (
    :ghsa, :schema_version, :modified, :published, :withdrawn, :cve, :ecosystems, :summary,
    :details, :severity, :cwes, :github_reviewed, :github_reviewed_at, :nvd_published_at, :ref_commits, :ref_pull_requests
)"#;

const INSERT_AFFECTED_PACKAGE: &str = r#"
INSERT INTO affected_packages (
     ghsa,  name,  ecosystem,  ranges,  versions
) VALUES (
    :ghsa, :name, :ecosystem, :ranges, :versions
)"#;

impl DB {
    pub fn new(db_path: &str) -> Result<Self, Box<dyn Error>> {
        let conn = Connection::open(db_path)?;
        conn.execute(CREATE_ADVISORIES_TABLE, ())?;
        conn.execute(CREATE_AFFECTED_PACKAGES_TABLE, ())?;
        Ok(Self {
            locked_conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn bulk_insert(
        &self,
        entries: &[osv::GitHubAdvisory],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut conn = self
            .locked_conn
            .lock()
            .map_err(|e| format!("obtaining connection lock: {}", e))?;
        let tx = conn.transaction()?;
        for entry in entries {
            // Collect ecosystems from affected packages
            let mut ecosystems = HashSet::new();
            if let Some(affected) = entry.affected.as_ref() {
                for a in affected {
                    ecosystems.insert(&a.package.ecosystem);
                }
            }
            let ecosystems_str = if ecosystems.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&ecosystems)?)
            };

            // Extract CVE from aliases (filter for aliases starting with "CVE-")
            let cve = entry
                .aliases
                .as_ref()
                .and_then(|aliases| aliases.iter().find(|alias| alias.starts_with("CVE-")))
                .map(|s| s.as_str());

            // Extract git commit URLs from references
            let mut commit_urls = HashSet::new();
            // Extract pull request URLs from references
            let mut pull_request_urls = HashSet::new();
            if let Some(references) = entry.references.as_ref() {
                for reference in references {
                    if let Some(commits) = extract_git_commits(&reference.url) {
                        commit_urls.extend(commits);
                    }
                    if let Some(pull_requests) = extract_pull_requests(&reference.url) {
                        pull_request_urls.extend(pull_requests);
                    }
                }
            }
            let ref_commits = if commit_urls.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&commit_urls)?)
            };
            let ref_pull_requests = if pull_request_urls.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&pull_request_urls)?)
            };

            tx.execute(
                INSERT_ADVISORY,
                params![
                    entry.id,
                    entry.schema_version,
                    entry.modified,
                    entry.published,
                    entry.withdrawn,
                    cve,
                    ecosystems_str,
                    entry.summary,
                    entry.details,
                    entry
                        .database_specific
                        .as_ref()
                        .map(|d| d.severity.as_ref()),
                    entry
                        .database_specific
                        .as_ref()
                        .and_then(|d| d.cwe_ids.as_ref())
                        .map(serde_json::to_value)
                        .transpose()?,
                    entry
                        .database_specific
                        .as_ref()
                        .and_then(|d| d.github_reviewed)
                        .map(|b| if b { 1 } else { 0 }),
                    entry
                        .database_specific
                        .as_ref()
                        .and_then(|d| d.github_reviewed_at.as_ref()),
                    entry
                        .database_specific
                        .as_ref()
                        .and_then(|d| d.nvd_published_at.as_ref())
                        .map(serde_json::to_string)
                        .transpose()?,
                    ref_commits,
                    ref_pull_requests
                ],
            )?;

            if let Some(affected) = entry.affected.as_ref() {
                for a in affected {
                    tx.execute(
                        INSERT_AFFECTED_PACKAGE,
                        params![
                            entry.id,
                            a.package.name,
                            serde_json::to_value(&a.package.ecosystem)?.as_str(),
                            serde_json::to_string(&a.ranges)?,
                            serde_json::to_string(&a.versions)?,
                        ],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}
