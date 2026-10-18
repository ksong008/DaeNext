use aya::programs::{
    links::{FdLink, LinkInfo},
    loaded_links,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AyaLinkMetadata {
    pub id: u32,
    pub program_id: u32,
    pub link_type: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AyaLinkMetadataReport {
    pub links: Vec<AyaLinkMetadata>,
    pub errors: Vec<String>,
}

fn metadata(info: &LinkInfo) -> Result<AyaLinkMetadata, String> {
    Ok(AyaLinkMetadata {
        id: info.id(),
        program_id: info.program_id(),
        link_type: format!(
            "{:?}",
            info.link_type().map_err(|error| format!("{error:?}"))?
        ),
    })
}

/// Observe a link already owned by the caller without transferring ownership.
pub fn describe_aya_fd_link(link: &FdLink) -> AyaLinkMetadataReport {
    match link
        .info()
        .map_err(|error| format!("{error:?}"))
        .and_then(|info| metadata(&info))
    {
        Ok(link) => AyaLinkMetadataReport {
            links: vec![link],
            errors: Vec::new(),
        },
        Err(error) => AyaLinkMetadataReport {
            links: Vec::new(),
            errors: vec![error],
        },
    }
}

/// Attach-time diagnostics for Aya-owned programs whose link wrappers expose no
/// borrowed FD. A matching program ID is evidence of association, not ownership:
/// this snapshot must never be used to decide which kernel links to delete.
pub fn query_aya_program_links(program_id: u32) -> AyaLinkMetadataReport {
    collect_program_links(
        program_id,
        loaded_links().map(|result| result.map_err(|error| format!("{error:?}"))),
    )
}

fn collect_program_links(
    program_id: u32,
    links: impl IntoIterator<Item = Result<LinkInfo, String>>,
) -> AyaLinkMetadataReport {
    let mut report = AyaLinkMetadataReport::default();
    for link in links {
        match link {
            Ok(info) if info.program_id() == program_id => match metadata(&info) {
                Ok(link) => report.links.push(link),
                Err(error) => report.errors.push(error),
            },
            Ok(_) => {}
            Err(error) => report.errors.push(error),
        }
    }
    report.links.sort_by_key(|link| link.id);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_failures_are_diagnostic_evidence() {
        let report =
            collect_program_links(123, [Err("EPERM while reading link metadata".to_owned())]);
        assert!(report.links.is_empty());
        assert_eq!(report.errors, ["EPERM while reading link metadata"]);
    }
}
