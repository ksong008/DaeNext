use super::{HttpRequest, HttpResponse, percent_decode, write_http_response_for_request};
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

const STATIC_FILE_CHUNK_BYTES: usize = 16 * 1024;
const STATIC_ASSET_HASH_SUFFIX_BYTES: usize = 8;
const STATIC_INDEX_CACHE_CONTROL: &str = "no-cache";
const STATIC_HASHED_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

pub fn write_static_file_response(
    stream: &mut TcpStream,
    web_root: &Path,
    request: &HttpRequest,
    head_only: bool,
) -> io::Result<()> {
    if request.method != "GET" && request.method != "HEAD" {
        let response = HttpResponse::json(
            405,
            serde_json::json!({"error": "method should be GET or HEAD"}),
        );
        return write_http_response_for_request(stream, request, &response, head_only);
    }
    let mut path = match safe_static_path(web_root, &request.path) {
        Some(path) => path,
        None => {
            let response =
                HttpResponse::json(400, serde_json::json!({"error": "invalid static path"}));
            return write_http_response_for_request(stream, request, &response, head_only);
        }
    };
    if path.is_dir() {
        path = path.join("index.html");
    }
    if !path.is_file() {
        path = web_root.join("index.html");
    }
    let mut file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            let response = HttpResponse::json(404, serde_json::json!({"error": error.to_string()}));
            return write_http_response_for_request(stream, request, &response, head_only);
        }
    };
    let content_length = file.metadata()?.len();
    let deadline = Instant::now()
        .checked_add(super::PRODUCT_HTTP_RESPONSE_WRITE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut head = Vec::with_capacity(256);
    let cache_control = static_cache_control(web_root, &path);
    write!(
        head,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: {}\r\n\r\n",
        mime_for_path(&path),
        content_length,
        cache_control,
    )?;
    super::write_all_with_deadline(stream, &head, deadline)?;
    if !head_only {
        let mut chunk = [0_u8; STATIC_FILE_CHUNK_BYTES];
        loop {
            let read = match file.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            super::write_all_with_deadline(stream, &chunk[..read], deadline)?;
        }
    }
    stream.set_write_timeout(Some(super::socket_timeout_until(
        deadline,
        "HTTP response write deadline exceeded",
    )?))?;
    stream.flush()
}

pub fn serve_static_file(web_root: &Path, request: &HttpRequest) -> HttpResponse {
    if request.method != "GET" && request.method != "HEAD" {
        return HttpResponse::json(
            405,
            serde_json::json!({"error": "method should be GET or HEAD"}),
        );
    }
    let mut path = match safe_static_path(web_root, &request.path) {
        Some(path) => path,
        None => {
            return HttpResponse::json(400, serde_json::json!({"error": "invalid static path"}));
        }
    };
    if path.is_dir() {
        path = path.join("index.html");
    }
    if !path.is_file() {
        path = web_root.join("index.html");
    }
    match fs::read(&path) {
        Ok(body) => {
            let mut response = HttpResponse::text(200, mime_for_path(&path), body);
            response.extra_headers.push((
                "Cache-Control".to_owned(),
                static_cache_control(web_root, &path).to_owned(),
            ));
            response
        }
        Err(err) => HttpResponse::json(404, serde_json::json!({"error": err.to_string()})),
    }
}

fn static_cache_control(web_root: &Path, path: &Path) -> &'static str {
    if is_content_hashed_asset(web_root, path) {
        STATIC_HASHED_ASSET_CACHE_CONTROL
    } else {
        STATIC_INDEX_CACHE_CONTROL
    }
}

fn is_content_hashed_asset(web_root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(web_root) else {
        return false;
    };
    if relative
        .components()
        .next()
        .is_none_or(|component| component.as_os_str() != "assets")
    {
        return false;
    }
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };
    let bytes = stem.as_bytes();
    let Some(hash_start) = bytes.len().checked_sub(STATIC_ASSET_HASH_SUFFIX_BYTES) else {
        return false;
    };
    bytes[..hash_start].contains(&b'-')
        && bytes[hash_start..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub fn safe_static_path(web_root: &Path, request_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(request_path);
    let trimmed = decoded.trim_start_matches('/');
    let mut path = PathBuf::from(web_root);
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(value) => path.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(path)
}

pub fn mime_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
    {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::find_subsequence;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn static_response_streams_the_complete_file_with_bounded_chunks() {
        let root = std::env::temp_dir().join(format!("dae-static-response-{}", fastrand::u64(..)));
        fs::create_dir_all(&root).unwrap();
        let body = vec![0x5a; STATIC_FILE_CHUNK_BYTES * 3 + 17];
        fs::write(root.join("asset.bin"), &body).unwrap();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let request = HttpRequest {
            method: "GET".to_owned(),
            path: "/asset.bin".to_owned(),
            query: std::collections::HashMap::new(),
            headers: std::collections::HashMap::new(),
            body: Vec::new(),
        };
        let writer = thread::spawn(move || {
            write_static_file_response(&mut server, &root, &request, false).unwrap();
            fs::remove_dir_all(root).unwrap();
        });
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        writer.join().unwrap();
        let body_start = find_subsequence(&response, b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&response[body_start..], body.as_slice());
        assert!(
            String::from_utf8_lossy(&response[..body_start])
                .contains(&format!("Content-Length: {}", body.len()))
        );
    }

    #[test]
    fn hashed_assets_are_immutable_while_index_stays_revalidated() {
        let root = std::env::temp_dir().join(format!("dae-static-cache-{}", fastrand::u64(..)));
        let assets = root.join("assets");
        fs::create_dir_all(&assets).unwrap();
        let index = root.join("index.html");
        let asset = assets.join("index-AbCd1234.js");
        let unhashed_asset = assets.join("runtime.js");
        fs::write(&index, b"index").unwrap();
        fs::write(&asset, b"asset").unwrap();
        fs::write(&unhashed_asset, b"runtime").unwrap();

        assert_eq!(
            static_cache_control(&root, &index),
            STATIC_INDEX_CACHE_CONTROL
        );
        assert_eq!(
            static_cache_control(&root, &asset),
            STATIC_HASHED_ASSET_CACHE_CONTROL
        );
        assert_eq!(
            static_cache_control(&root, &unhashed_asset),
            STATIC_INDEX_CACHE_CONTROL
        );

        fs::remove_dir_all(root).unwrap();
    }
}
