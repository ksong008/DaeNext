use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::Arc;

use boring::asn1::Asn1Time;
use boring::bn::{BigNum, MsbOption};
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::ssl::{
    AlpnError, SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion,
};
use boring::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use boring::x509::{X509, X509NameBuilder};
use quinn_boring::QuicSslContext;

use dae_outbound_core::error::OutboundError;

#[derive(Clone)]
pub struct TestTlsIdentity {
    pub certificate: X509,
    pub private_key: PKey<Private>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestCertificateValidity {
    Current,
    Expired,
    NotYetValid,
}

#[derive(Clone)]
pub struct TestTlsCertificateChain {
    pub root_certificate: X509,
    pub leaf_identity: TestTlsIdentity,
}

impl TestTlsCertificateChain {
    pub fn root_pem(&self) -> Result<Vec<u8>, OutboundError> {
        self.root_certificate
            .to_pem()
            .map_err(|error| test_tls_error(format!("encode root certificate PEM: {error}")))
    }
}

impl TestTlsIdentity {
    pub fn certificate_der(&self) -> Result<Vec<u8>, OutboundError> {
        self.certificate
            .to_der()
            .map_err(|error| test_tls_error(format!("encode certificate DER: {error}")))
    }
}

pub fn self_signed_tls_identity(
    server_names: &[impl AsRef<str>],
) -> Result<TestTlsIdentity, OutboundError> {
    let common_name = server_names
        .first()
        .map(AsRef::as_ref)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| test_tls_error("test TLS identity requires a server name"))?;
    let private_key = PKey::from_rsa(
        Rsa::generate(2048)
            .map_err(|error| test_tls_error(format!("generate RSA key: {error}")))?,
    )
    .map_err(|error| test_tls_error(format!("create private key: {error}")))?;

    let mut name = X509NameBuilder::new()
        .map_err(|error| test_tls_error(format!("create certificate name: {error}")))?;
    name.append_entry_by_text("CN", common_name)
        .map_err(|error| test_tls_error(format!("set certificate common name: {error}")))?;
    let name = name.build();

    let mut certificate = X509::builder()
        .map_err(|error| test_tls_error(format!("create certificate builder: {error}")))?;
    certificate
        .set_version(2)
        .map_err(|error| test_tls_error(format!("set certificate version: {error}")))?;
    let mut serial = BigNum::new()
        .map_err(|error| test_tls_error(format!("create certificate serial: {error}")))?;
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .map_err(|error| test_tls_error(format!("randomize certificate serial: {error}")))?;
    let serial = serial
        .to_asn1_integer()
        .map_err(|error| test_tls_error(format!("encode certificate serial: {error}")))?;
    certificate
        .set_serial_number(&serial)
        .map_err(|error| test_tls_error(format!("set certificate serial: {error}")))?;
    certificate
        .set_subject_name(&name)
        .and_then(|()| certificate.set_issuer_name(&name))
        .and_then(|()| certificate.set_pubkey(&private_key))
        .map_err(|error| test_tls_error(format!("set certificate identity: {error}")))?;
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|error| test_tls_error(format!("set certificate not-before: {error}")))?;
    let not_after = Asn1Time::days_from_now(30)
        .map_err(|error| test_tls_error(format!("set certificate not-after: {error}")))?;
    certificate
        .set_not_before(&not_before)
        .and_then(|()| certificate.set_not_after(&not_after))
        .map_err(|error| test_tls_error(format!("set certificate validity: {error}")))?;
    certificate
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .map_err(|error| test_tls_error(format!("build basic constraints: {error}")))?
                .as_ref(),
        )
        .map_err(|error| test_tls_error(format!("append basic constraints: {error}")))?;
    certificate
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|error| test_tls_error(format!("build key usage: {error}")))?
                .as_ref(),
        )
        .map_err(|error| test_tls_error(format!("append key usage: {error}")))?;
    certificate
        .append_extension(
            ExtendedKeyUsage::new()
                .server_auth()
                .build()
                .map_err(|error| test_tls_error(format!("build extended key usage: {error}")))?
                .as_ref(),
        )
        .map_err(|error| test_tls_error(format!("append extended key usage: {error}")))?;
    let mut alternative_names = SubjectAlternativeName::new();
    for server_name in server_names {
        let server_name = server_name.as_ref();
        if server_name.parse::<IpAddr>().is_ok() {
            alternative_names.ip(server_name);
        } else {
            alternative_names.dns(server_name);
        }
    }
    let alternative_names = alternative_names
        .build(&certificate.x509v3_context(None, None))
        .map_err(|error| test_tls_error(format!("build subject alternative names: {error}")))?;
    certificate
        .append_extension(&alternative_names)
        .map_err(|error| test_tls_error(format!("append subject alternative names: {error}")))?;
    certificate
        .sign(&private_key, MessageDigest::sha256())
        .map_err(|error| test_tls_error(format!("sign certificate: {error}")))?;

    Ok(TestTlsIdentity {
        certificate: certificate.build(),
        private_key,
    })
}

pub fn signed_tls_certificate_chain(
    server_name: &str,
    validity: TestCertificateValidity,
) -> Result<TestTlsCertificateChain, OutboundError> {
    if server_name.is_empty() {
        return Err(test_tls_error("test TLS chain requires a server name"));
    }

    let root_key = PKey::from_rsa(
        Rsa::generate(2048)
            .map_err(|error| test_tls_error(format!("generate root RSA key: {error}")))?,
    )
    .map_err(|error| test_tls_error(format!("create root private key: {error}")))?;
    let root_name = certificate_name("DaeNext BoringSSL test root")?;
    let mut root = X509::builder()
        .map_err(|error| test_tls_error(format!("create root certificate builder: {error}")))?;
    root.set_version(2)
        .and_then(|()| set_random_serial(&mut root))
        .and_then(|()| root.set_subject_name(&root_name))
        .and_then(|()| root.set_issuer_name(&root_name))
        .and_then(|()| root.set_pubkey(&root_key))
        .map_err(|error| test_tls_error(format!("configure root certificate identity: {error}")))?;
    let root_not_before = Asn1Time::days_from_now(0)
        .map_err(|error| test_tls_error(format!("set root not-before: {error}")))?;
    let root_not_after = Asn1Time::days_from_now(3650)
        .map_err(|error| test_tls_error(format!("set root not-after: {error}")))?;
    root.set_not_before(&root_not_before)
        .and_then(|()| root.set_not_after(&root_not_after))
        .map_err(|error| test_tls_error(format!("set root validity: {error}")))?;
    let root_constraints = BasicConstraints::new()
        .critical()
        .ca()
        .build()
        .map_err(|error| test_tls_error(format!("build root basic constraints: {error}")))?;
    let root_key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_cert_sign()
        .crl_sign()
        .build()
        .map_err(|error| test_tls_error(format!("build root key usage: {error}")))?;
    root.append_extension(&root_constraints)
        .and_then(|()| root.append_extension(&root_key_usage))
        .map_err(|error| test_tls_error(format!("append root certificate extensions: {error}")))?;
    let root_key_identifier = SubjectKeyIdentifier::new()
        .build(&root.x509v3_context(None, None))
        .map_err(|error| test_tls_error(format!("build root key identifier: {error}")))?;
    root.append_extension(&root_key_identifier)
        .map_err(|error| test_tls_error(format!("append root key identifier: {error}")))?;
    root.sign(&root_key, MessageDigest::sha256())
        .map_err(|error| test_tls_error(format!("sign root certificate: {error}")))?;
    let root_certificate = root.build();

    let leaf_key = PKey::from_rsa(
        Rsa::generate(2048)
            .map_err(|error| test_tls_error(format!("generate leaf RSA key: {error}")))?,
    )
    .map_err(|error| test_tls_error(format!("create leaf private key: {error}")))?;
    let leaf_name = certificate_name(server_name)?;
    let mut leaf = X509::builder()
        .map_err(|error| test_tls_error(format!("create leaf certificate builder: {error}")))?;
    leaf.set_version(2)
        .and_then(|()| set_random_serial(&mut leaf))
        .and_then(|()| leaf.set_subject_name(&leaf_name))
        .and_then(|()| leaf.set_issuer_name(root_certificate.subject_name()))
        .and_then(|()| leaf.set_pubkey(&leaf_key))
        .map_err(|error| test_tls_error(format!("configure leaf certificate identity: {error}")))?;
    let (leaf_not_before, leaf_not_after) = certificate_validity(validity)?;
    leaf.set_not_before(&leaf_not_before)
        .and_then(|()| leaf.set_not_after(&leaf_not_after))
        .map_err(|error| test_tls_error(format!("set leaf validity: {error}")))?;
    let leaf_constraints = BasicConstraints::new()
        .critical()
        .build()
        .map_err(|error| test_tls_error(format!("build leaf basic constraints: {error}")))?;
    let leaf_key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()
        .map_err(|error| test_tls_error(format!("build leaf key usage: {error}")))?;
    let leaf_extended_key_usage = ExtendedKeyUsage::new()
        .server_auth()
        .build()
        .map_err(|error| test_tls_error(format!("build leaf extended key usage: {error}")))?;
    leaf.append_extension(&leaf_constraints)
        .and_then(|()| leaf.append_extension(&leaf_key_usage))
        .and_then(|()| leaf.append_extension(&leaf_extended_key_usage))
        .map_err(|error| test_tls_error(format!("append leaf certificate extensions: {error}")))?;
    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&leaf.x509v3_context(Some(&root_certificate), None))
        .map_err(|error| test_tls_error(format!("build authority key identifier: {error}")))?;
    leaf.append_extension(&authority_key_identifier)
        .map_err(|error| test_tls_error(format!("append authority key identifier: {error}")))?;
    let alternative_names = SubjectAlternativeName::new()
        .dns(server_name)
        .build(&leaf.x509v3_context(Some(&root_certificate), None))
        .map_err(|error| test_tls_error(format!("build leaf subject alternative name: {error}")))?;
    leaf.append_extension(&alternative_names)
        .and_then(|()| leaf.sign(&root_key, MessageDigest::sha256()))
        .map_err(|error| test_tls_error(format!("sign leaf certificate: {error}")))?;

    Ok(TestTlsCertificateChain {
        root_certificate,
        leaf_identity: TestTlsIdentity {
            certificate: leaf.build(),
            private_key: leaf_key,
        },
    })
}

pub fn tls13_acceptor(
    identity: &TestTlsIdentity,
    alpn_protocols: &[Vec<u8>],
) -> Result<SslAcceptor, OutboundError> {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|error| test_tls_error(format!("create TLS acceptor: {error}")))?;
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .and_then(|()| acceptor.set_max_proto_version(Some(SslVersion::TLS1_3)))
        .and_then(|()| acceptor.set_certificate(&identity.certificate))
        .and_then(|()| acceptor.set_private_key(&identity.private_key))
        .and_then(|()| acceptor.check_private_key())
        .map_err(|error| test_tls_error(format!("configure TLS acceptor: {error}")))?;
    let accepted_alpn = alpn_protocols.to_vec();
    acceptor.set_alpn_select_callback(move |_ssl, client| {
        select_client_alpn(&accepted_alpn, client).ok_or(AlpnError::NOACK)
    });
    Ok(acceptor.build())
}

pub fn tls13_connector(
    identity: &TestTlsIdentity,
    alpn_protocols: &[Vec<u8>],
) -> Result<SslConnector, OutboundError> {
    let mut connector = SslConnector::builder(SslMethod::tls())
        .map_err(|error| test_tls_error(format!("create TLS connector: {error}")))?;
    connector
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .and_then(|()| connector.set_max_proto_version(Some(SslVersion::TLS1_3)))
        .map_err(|error| test_tls_error(format!("configure TLS versions: {error}")))?;
    connector.set_verify(SslVerifyMode::PEER);
    connector
        .cert_store_mut()
        .add_cert(identity.certificate.clone())
        .map_err(|error| test_tls_error(format!("install test trust anchor: {error}")))?;
    connector
        .set_alpn_protos(&alpn_wire(alpn_protocols)?)
        .map_err(|error| test_tls_error(format!("configure client ALPN: {error}")))?;
    Ok(connector.build())
}

pub fn connect_tls_stream<S>(
    connector: &SslConnector,
    server_name: &str,
    stream: S,
) -> Result<SslStream<S>, OutboundError>
where
    S: Read + Write,
{
    connector
        .connect(server_name, stream)
        .map_err(|error| test_tls_error(format!("connect BoringSSL test stream: {error}")))
}

pub fn boring_quic_server_config(
    identity: &TestTlsIdentity,
    alpn_protocols: &[Vec<u8>],
    transport: Arc<quinn::TransportConfig>,
) -> Result<quinn::ServerConfig, OutboundError> {
    let mut crypto = quinn_boring::ServerConfig::new()
        .map_err(|error| test_tls_error(format!("create BoringSSL QUIC server: {error}")))?;
    crypto
        .set_alpn(alpn_protocols)
        .map_err(|error| test_tls_error(format!("configure QUIC server ALPN: {error}")))?;
    crypto
        .ctx_mut()
        .set_certificate(identity.certificate.clone())
        .and_then(|()| {
            crypto
                .ctx_mut()
                .set_private_key(identity.private_key.clone())
        })
        .and_then(|()| crypto.ctx_mut().check_private_key())
        .map_err(|error| test_tls_error(format!("configure QUIC server identity: {error}")))?;
    let mut config = quinn_boring::helpers::server_config(Arc::new(crypto))
        .map_err(|error| test_tls_error(format!("build QUIC server config: {error}")))?;
    config.transport_config(transport);
    Ok(config)
}

pub fn boring_quic_server_endpoint(
    config: quinn::ServerConfig,
    address: std::net::SocketAddr,
) -> std::io::Result<quinn::Endpoint> {
    quinn_boring::helpers::server_endpoint(config, address)
}

pub fn boring_quic_client_endpoint(
    address: std::net::SocketAddr,
) -> std::io::Result<quinn::Endpoint> {
    quinn_boring::helpers::client_endpoint(address)
}

pub fn selected_tls_alpn(ssl: &boring::ssl::SslRef) -> String {
    ssl.selected_alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
        .unwrap_or_default()
}

fn alpn_wire(protocols: &[Vec<u8>]) -> Result<Vec<u8>, OutboundError> {
    let mut wire = Vec::new();
    for protocol in protocols {
        let len = u8::try_from(protocol.len())
            .map_err(|_| test_tls_error("ALPN protocol exceeds 255 bytes"))?;
        if len == 0 {
            return Err(test_tls_error("ALPN protocol cannot be empty"));
        }
        wire.push(len);
        wire.extend_from_slice(protocol);
    }
    Ok(wire)
}

fn select_client_alpn<'a>(accepted: &[Vec<u8>], mut client: &'a [u8]) -> Option<&'a [u8]> {
    while let Some((&len, rest)) = client.split_first() {
        let len = usize::from(len);
        if rest.len() < len {
            return None;
        }
        let (protocol, remaining) = rest.split_at(len);
        if accepted.iter().any(|candidate| candidate == protocol) {
            return Some(protocol);
        }
        client = remaining;
    }
    None
}

fn certificate_name(common_name: &str) -> Result<boring::x509::X509Name, OutboundError> {
    let mut name = X509NameBuilder::new()
        .map_err(|error| test_tls_error(format!("create certificate name: {error}")))?;
    name.append_entry_by_text("CN", common_name)
        .map_err(|error| test_tls_error(format!("set certificate common name: {error}")))?;
    Ok(name.build())
}

fn set_random_serial(
    builder: &mut boring::x509::X509Builder,
) -> Result<(), boring::error::ErrorStack> {
    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    builder.set_serial_number(&serial)
}

fn certificate_validity(
    validity: TestCertificateValidity,
) -> Result<(Asn1Time, Asn1Time), OutboundError> {
    let times = match validity {
        TestCertificateValidity::Current => {
            (Asn1Time::days_from_now(0), Asn1Time::days_from_now(30))
        }
        TestCertificateValidity::Expired => (
            Asn1Time::from_unix(1_262_304_000),
            Asn1Time::from_unix(1_293_840_000),
        ),
        TestCertificateValidity::NotYetValid => (
            Asn1Time::from_unix(4_070_908_800),
            Asn1Time::from_unix(4_102_444_800),
        ),
    };
    Ok((
        times
            .0
            .map_err(|error| test_tls_error(format!("set certificate not-before: {error}")))?,
        times
            .1
            .map_err(|error| test_tls_error(format!("set certificate not-after: {error}")))?,
    ))
}

fn test_tls_error(message: impl Into<String>) -> OutboundError {
    OutboundError::BadSharedTransport(message.into())
}
