pub(super) fn help_text() -> String {
    r#"daed Rust native product commands:
  daed --version
  daed run -c /etc/daed --listen 0.0.0.0:2023 [--api-only] [--web-root PATH] [--control PATH]
  daed reload [--control PATH] [--timeout 60s] [--json]
  daed wait-ready [--control PATH] [--timeout 60s] [--json]
  daed validate -c /etc/daed/|/etc/dae/config.dae [--state /etc/daed/daed.db] [--runtime] [--json]
  daed service-contract [--json]
  daed package-info [--json]
  daed resident-adapter-matrix -c /etc/dae/config.dae [--json]
  daed resident-adapter-udp-live -c /etc/dae/config.dae --target HOST:PORT [--payload TEXT|--payload-hex HEX] [--json]
  daed state check --state /etc/daed/daed.db
  daed state migrate --from-wing-db /etc/daed/wing.db --to /etc/daed/daed.db [--force]
  daed export openapi|flatdesc|outline|package-manifest|admission-report|webui-route-audit|systemd-unit|docker-entrypoint
  daed resetpass -c /etc/daed [--json]
"#
    .to_owned()
}
