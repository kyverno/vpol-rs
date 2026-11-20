use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cel::common::types::STRING_TYPE;
use cel::common::value::CowVal;
use cel::{DeclarationError, Env, ExecutionError, Library};
use kube_cel::cel;
use num_bigint::BigUint;
use serde_json::{Value as Json, json};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::der_parser::oid::Oid;
use x509_parser::extensions::{
    DistributionPointName, GeneralName, GeneralSubtree, ParsedExtension, X509Extension,
};
use x509_parser::prelude::{FromDer as _, X509Certificate, X509Name};
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::common::{json_to_value, string_arg, to_cow};

/// Kyverno's `x509` CEL library: `x509.decode(pem) -> map`, which decodes a PEM
/// `CERTIFICATE` or `CERTIFICATE REQUEST` into the map Kyverno builds from Go's
/// `x509.Certificate` / `x509.CertificateRequest`. Only RSA keys are supported,
/// as in Kyverno.
pub struct X509Lib;

impl X509Lib {
    pub fn new() -> Self {
        X509Lib
    }
}

impl Library for X509Lib {
    fn name(&self) -> Option<&str> {
        Some("kyverno.x509")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        env.add_overload(
            "x509.decode",
            "x509_decode_string",
            vec![STRING_TYPE],
            decode,
        )
    }
}

fn err(message: impl std::fmt::Display) -> ExecutionError {
    ExecutionError::function_error("x509.decode", message)
}

// cel's `Function` type takes the arguments by value.
#[allow(clippy::needless_pass_by_value)]
fn decode<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let input = string_arg(&args, 0)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(input.as_bytes())
        .map_err(|_| err("failed to decode PEM block"))?;
    let decoded = match pem.label.as_str() {
        "CERTIFICATE" => {
            let cert = pem.parse_x509().map_err(err)?;
            certificate(&cert, &pem.contents)?
        }
        "CERTIFICATE REQUEST" => {
            let (_, csr) = X509CertificationRequest::from_der(&pem.contents).map_err(err)?;
            certificate_request(&csr, &pem.contents)?
        }
        _ => {
            return Err(err(
                "PEM block neither contains a CERTIFICATE or CERTIFICATE REQUEST",
            ));
        }
    };
    to_cow(json_to_value(&decoded))
}

/// The certificate, with the fields of Kyverno's `CertificateOutput`.
fn certificate(cert: &X509Certificate<'_>, raw: &[u8]) -> Result<Json, ExecutionError> {
    let tbs = &cert.tbs_certificate;
    let ext = Extensions::collect(tbs.extensions());
    let (max_path_len, max_path_len_zero) = match &ext.basic_constraints {
        Some((_, Some(len))) => (i64::from(*len), *len == 0),
        Some((_, None)) => (-1, false),
        None => (0, false),
    };
    // Go's `big.Int.Int64`: the low 64 bits.
    #[allow(clippy::cast_possible_wrap)]
    let serial = tbs.serial.iter_u64_digits().next().unwrap_or(0) as i64;

    Ok(json!({
        "Raw": BASE64.encode(raw),
        "RawTBSCertificate": BASE64.encode(tbs.as_ref()),
        "RawSubjectPublicKeyInfo": BASE64.encode(tbs.subject_pki.raw),
        "RawSubject": BASE64.encode(tbs.subject.as_raw()),
        "RawIssuer": BASE64.encode(tbs.issuer.as_raw()),
        "Signature": BASE64.encode(&cert.signature_value.data),
        "PublicKeyAlgorithm": 1,
        "PublicKey": rsa_public_key(&tbs.subject_pki)?,
        "SerialNumber": serial,
        "Issuer": name(&tbs.issuer, true)?,
        "NotBefore": rfc3339(tbs.validity.not_before.timestamp()),
        "NotAfter": rfc3339(tbs.validity.not_after.timestamp()),
        "KeyUsage": ext.key_usage,
        "Extensions": or_null(extensions(tbs.extensions())),
        "ExtraExtensions": null,
        "ExtKeyUsage": or_null(ext.ext_key_usage),
        "BasicConstraintsValid": ext.basic_constraints.is_some(),
        "IsCA": ext.basic_constraints.is_some_and(|(ca, _)| ca),
        "MaxPathLen": max_path_len,
        "MaxPathLenZero": max_path_len_zero,
        "AuthorityKeyId": ext.authority_key_id.map(|id| BASE64.encode(id)),
        "OCSPServer": or_null(ext.ocsp_servers),
        "IssuingCertificateURL": or_null(ext.issuing_certificate_urls),
        "DNSNames": or_null(ext.sans.dns),
        "EmailAddresses": or_null(ext.sans.emails),
        "IPAddresses": or_null(ext.sans.ips),
        "PermittedDNSDomainsCritical": ext.name_constraints_critical,
        "PermittedDNSDomains": or_null(ext.permitted.dns),
        "ExcludedDNSDomains": or_null(ext.excluded.dns),
        "PermittedIPRanges": or_null(ext.permitted.ip_ranges),
        "ExcludedIPRanges": or_null(ext.excluded.ip_ranges),
        "PermittedEmailAddresses": or_null(ext.permitted.emails),
        "ExcludedEmailAddresses": or_null(ext.excluded.emails),
        "PermittedURIDomains": or_null(ext.permitted.uri_domains),
        "ExcludedURIDomains": or_null(ext.excluded.uri_domains),
        "CRLDistributionPoints": or_null(ext.crl_distribution_points),
        "PolicyIdentifiers": or_null(ext.policy_identifiers),
    }))
}

/// The certificate request, with the fields of Go's `x509.CertificateRequest`.
/// Its deprecated `Attributes` field is left null.
fn certificate_request(
    csr: &X509CertificationRequest<'_>,
    raw: &[u8],
) -> Result<Json, ExecutionError> {
    let info = &csr.certification_request_info;
    let mut sans = Sans::default();
    let mut extensions_json = Vec::new();
    if let Some(parsed) = csr.requested_extensions() {
        for extension in parsed {
            if let ParsedExtension::SubjectAlternativeName(san) = extension {
                sans.add(&san.general_names);
            }
        }
    }
    // The raw extensions, as Go reports them, from the extensionRequest attribute.
    for attribute in info.iter_attributes() {
        if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(req) =
            attribute.parsed_attribute()
        {
            extensions_json.extend(extensions(&req.extensions));
        }
    }

    Ok(json!({
        "Raw": BASE64.encode(raw),
        "RawTBSCertificateRequest": BASE64.encode(info.raw),
        "RawSubjectPublicKeyInfo": BASE64.encode(info.subject_pki.raw),
        "RawSubject": BASE64.encode(info.subject.as_raw()),
        "Version": info.version.0,
        "Signature": BASE64.encode(&csr.signature_value.data),
        "SignatureAlgorithm": signature_algorithm(&csr.signature_algorithm),
        "PublicKeyAlgorithm": 1,
        "PublicKey": rsa_public_key(&info.subject_pki)?,
        "Subject": name(&info.subject, false)?,
        "Attributes": null,
        "Extensions": or_null(extensions_json),
        "ExtraExtensions": null,
        "DNSNames": or_null(sans.dns),
        "EmailAddresses": or_null(sans.emails),
        "IPAddresses": or_null(sans.ips),
        "URIs": or_null(sans.uris.iter().map(|u| go_url(u)).collect()),
    }))
}

/// The RSA key as `{N: decimal string, E: int}`; any other key is an error.
fn rsa_public_key(spki: &SubjectPublicKeyInfo<'_>) -> Result<Json, ExecutionError> {
    let Ok(PublicKey::RSA(key)) = spki.parsed() else {
        return Err(err("certificate should use rsa algorithm"));
    };
    let exponent = key
        .try_exponent()
        .map_err(|_| err("failed to parse subject public key info"))?;
    Ok(json!({
        "N": BigUint::from_bytes_be(key.modulus).to_string(),
        "E": exponent,
    }))
}

/// A name as Go's `pkix.Name` encodes it. With `strict`, as when Go parses a
/// certificate, a value that isn't a string is an error; otherwise it's null.
fn name(name: &X509Name<'_>, strict: bool) -> Result<Json, ExecutionError> {
    let mut fields: [(&str, &str, Vec<String>); 7] = [
        ("2.5.4.6", "Country", Vec::new()),
        ("2.5.4.10", "Organization", Vec::new()),
        ("2.5.4.11", "OrganizationalUnit", Vec::new()),
        ("2.5.4.7", "Locality", Vec::new()),
        ("2.5.4.8", "Province", Vec::new()),
        ("2.5.4.9", "StreetAddress", Vec::new()),
        ("2.5.4.17", "PostalCode", Vec::new()),
    ];
    let (mut common_name, mut serial_number) = (String::new(), String::new());
    let mut names = Vec::new();
    for attribute in name.iter_attributes() {
        let oid = attribute.attr_type();
        let value = attribute_string(attribute.attr_value());
        if value.is_none() && strict {
            return Err(err(format!(
                "invalid RDNSequence: unsupported value for {}",
                oid.to_id_string()
            )));
        }
        names.push(json!({ "Type": oid_json(oid), "Value": value }));
        let Some(value) = value else { continue };
        match oid.to_id_string().as_str() {
            "2.5.4.3" => common_name = value,
            "2.5.4.5" => serial_number = value,
            id => {
                if let Some((_, _, list)) = fields.iter_mut().find(|(o, _, _)| *o == id) {
                    list.push(value);
                }
            }
        }
    }
    let mut out = serde_json::Map::new();
    for (_, field, list) in fields {
        out.insert(
            field.to_owned(),
            or_null(list.into_iter().map(Json::from).collect()),
        );
    }
    out.insert("CommonName".to_owned(), common_name.into());
    out.insert("SerialNumber".to_owned(), serial_number.into());
    out.insert("Names".to_owned(), or_null(names));
    out.insert("ExtraNames".to_owned(), Json::Null);
    Ok(Json::Object(out))
}

/// An attribute value as a string, for the ASN.1 string types Go decodes.
fn attribute_string(value: &x509_parser::der_parser::asn1_rs::Any<'_>) -> Option<String> {
    let data = value.data;
    match value.header.tag().0 {
        // UTF8String, NumericString, PrintableString, IA5String
        12 | 18 | 19 | 22 => std::str::from_utf8(data).ok().map(str::to_owned),
        // T61String, as Latin-1
        20 => Some(data.iter().map(|&b| char::from(b)).collect()),
        // UniversalString: UTF-32BE
        28 => data
            .chunks_exact(4)
            .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
            .collect(),
        // BMPString: UTF-16BE
        30 => String::from_utf16(
            &data
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        )
        .ok(),
        _ => None,
    }
}

/// Extensions as Go's `pkix.Extension` encodes them.
fn extensions(extensions: &[X509Extension<'_>]) -> Vec<Json> {
    extensions
        .iter()
        .map(|e| {
            json!({
                "Id": oid_json(&e.oid),
                "Critical": e.critical,
                "Value": BASE64.encode(e.value),
            })
        })
        .collect()
}

/// The parsed extensions Kyverno reports fields from.
#[derive(Default)]
struct Extensions {
    key_usage: u16,
    ext_key_usage: Vec<Json>,
    basic_constraints: Option<(bool, Option<u32>)>,
    authority_key_id: Option<Vec<u8>>,
    ocsp_servers: Vec<Json>,
    issuing_certificate_urls: Vec<Json>,
    sans: Sans,
    name_constraints_critical: bool,
    permitted: Subtrees,
    excluded: Subtrees,
    crl_distribution_points: Vec<Json>,
    policy_identifiers: Vec<Json>,
}

impl Extensions {
    fn collect(extensions: &[X509Extension<'_>]) -> Self {
        let mut out = Extensions::default();
        for extension in extensions {
            match extension.parsed_extension() {
                ParsedExtension::KeyUsage(ku) => {
                    // Go's KeyUsage bits, from DigitalSignature (1 << 0) on.
                    let bits = [
                        ku.digital_signature(),
                        ku.non_repudiation(),
                        ku.key_encipherment(),
                        ku.data_encipherment(),
                        ku.key_agreement(),
                        ku.key_cert_sign(),
                        ku.crl_sign(),
                        ku.encipher_only(),
                        ku.decipher_only(),
                    ];
                    out.key_usage = bits
                        .iter()
                        .enumerate()
                        .filter(|(_, set)| **set)
                        .fold(0, |acc, (bit, _)| acc | (1 << bit));
                }
                ParsedExtension::ExtendedKeyUsage(_) => {
                    // In the certificate's order, duplicates kept, as Go reports them.
                    if let Ok((_, oids)) = <Vec<Oid<'_>>>::from_der(extension.value) {
                        out.ext_key_usage = oids
                            .iter()
                            .filter_map(ext_key_usage)
                            .map(Json::from)
                            .collect();
                    }
                }
                ParsedExtension::BasicConstraints(bc) => {
                    out.basic_constraints = Some((bc.ca, bc.path_len_constraint));
                }
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    out.authority_key_id = aki.key_identifier.as_ref().map(|k| k.0.to_vec());
                }
                ParsedExtension::AuthorityInfoAccess(aia) => {
                    for desc in &aia.accessdescs {
                        let GeneralName::URI(uri) = desc.access_location else {
                            continue;
                        };
                        match desc.access_method.to_id_string().as_str() {
                            "1.3.6.1.5.5.7.48.1" => out.ocsp_servers.push(uri.into()),
                            "1.3.6.1.5.5.7.48.2" => out.issuing_certificate_urls.push(uri.into()),
                            _ => {}
                        }
                    }
                }
                ParsedExtension::SubjectAlternativeName(san) => out.sans.add(&san.general_names),
                ParsedExtension::NameConstraints(nc) => {
                    out.name_constraints_critical = extension.critical;
                    out.permitted.add(nc.permitted_subtrees.as_deref());
                    out.excluded.add(nc.excluded_subtrees.as_deref());
                }
                ParsedExtension::CRLDistributionPoints(points) => {
                    for point in &points.points {
                        if let Some(DistributionPointName::FullName(names)) =
                            &point.distribution_point
                        {
                            // Go stops at the first name that isn't a URI.
                            for name in names {
                                let GeneralName::URI(uri) = name else { break };
                                out.crl_distribution_points.push((*uri).into());
                            }
                        }
                    }
                }
                ParsedExtension::CertificatePolicies(policies) => {
                    out.policy_identifiers =
                        policies.iter().map(|p| oid_json(&p.policy_id)).collect();
                }
                _ => {}
            }
        }
        out
    }
}

/// Subject alternative names, by kind.
#[derive(Default)]
struct Sans {
    dns: Vec<Json>,
    emails: Vec<Json>,
    ips: Vec<Json>,
    uris: Vec<String>,
}

impl Sans {
    fn add(&mut self, names: &[GeneralName<'_>]) {
        for name in names {
            match name {
                GeneralName::DNSName(dns) => self.dns.push((*dns).into()),
                GeneralName::RFC822Name(email) => self.emails.push((*email).into()),
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ip_addr(bytes) {
                        self.ips.push(ip.to_string().into());
                    }
                }
                GeneralName::URI(uri) => self.uris.push((*uri).to_owned()),
                _ => {}
            }
        }
    }
}

/// Name constraint subtrees, by kind.
#[derive(Default)]
struct Subtrees {
    dns: Vec<Json>,
    ip_ranges: Vec<Json>,
    emails: Vec<Json>,
    uri_domains: Vec<Json>,
}

impl Subtrees {
    fn add(&mut self, subtrees: Option<&[GeneralSubtree<'_>]>) {
        for subtree in subtrees.unwrap_or_default() {
            match &subtree.base {
                GeneralName::DNSName(dns) => self.dns.push((*dns).into()),
                GeneralName::RFC822Name(email) => self.emails.push((*email).into()),
                GeneralName::URI(domain) => self.uri_domains.push((*domain).into()),
                // An address and a mask of the same length, as Go's `net.IPNet`.
                GeneralName::IPAddress(bytes) => {
                    let (ip, mask) = bytes.split_at(bytes.len() / 2);
                    if let Some(ip) = ip_addr(ip) {
                        self.ip_ranges
                            .push(json!({ "IP": ip.to_string(), "Mask": BASE64.encode(mask) }));
                    }
                }
                _ => {}
            }
        }
    }
}

fn ip_addr(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes)
            .ok()
            .map(|b| Ipv4Addr::from(b).into()),
        16 => <[u8; 16]>::try_from(bytes)
            .ok()
            .map(|b| Ipv6Addr::from(b).into()),
        _ => None,
    }
}

/// Go's `ExtKeyUsage` value for an extended key usage OID it knows.
fn ext_key_usage(oid: &Oid<'_>) -> Option<u8> {
    Some(match oid.to_id_string().as_str() {
        "2.5.29.37.0" => 0,
        "1.3.6.1.5.5.7.3.1" => 1,
        "1.3.6.1.5.5.7.3.2" => 2,
        "1.3.6.1.5.5.7.3.3" => 3,
        "1.3.6.1.5.5.7.3.4" => 4,
        "1.3.6.1.5.5.7.3.5" => 5,
        "1.3.6.1.5.5.7.3.6" => 6,
        "1.3.6.1.5.5.7.3.7" => 7,
        "1.3.6.1.5.5.7.3.8" => 8,
        "1.3.6.1.5.5.7.3.9" => 9,
        "1.3.6.1.4.1.311.10.3.3" => 10,
        "2.16.840.1.113730.4.1" => 11,
        "1.3.6.1.4.1.311.2.1.22" => 12,
        "1.3.6.1.4.1.311.61.1.1" => 13,
        _ => return None,
    })
}

/// Go's `x509.SignatureAlgorithm` value for a signature algorithm.
fn signature_algorithm(algorithm: &x509_parser::x509::AlgorithmIdentifier<'_>) -> u8 {
    match algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.2" => 1,
        "1.2.840.113549.1.1.4" => 2,
        // sha1WithRSAEncryption, and its legacy OID
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => 3,
        "1.2.840.113549.1.1.11" => 4,
        "1.2.840.113549.1.1.12" => 5,
        "1.2.840.113549.1.1.13" => 6,
        "1.2.840.10040.4.3" => 7,
        "2.16.840.1.101.3.4.3.2" => 8,
        "1.2.840.10045.4.1" => 9,
        "1.2.840.10045.4.3.2" => 10,
        "1.2.840.10045.4.3.3" => 11,
        "1.2.840.10045.4.3.4" => 12,
        // RSASSA-PSS: told apart by the hash in its parameters.
        "1.2.840.113549.1.1.10" => pss_hash(algorithm),
        "1.3.101.112" => 16,
        _ => 0,
    }
}

/// The `SignatureAlgorithm` of an RSASSA-PSS signature, by the SHA-2 hash its
/// parameters name: SHA-256 is 13, SHA-384 14 and SHA-512 15; anything else 0.
fn pss_hash(algorithm: &x509_parser::x509::AlgorithmIdentifier<'_>) -> u8 {
    // The DER encodings of the SHA-256, SHA-384 and SHA-512 OIDs.
    const SHA2: [([u8; 11], u8); 3] = [
        ([6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1], 13),
        ([6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2], 14),
        ([6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3], 15),
    ];
    let Some(params) = &algorithm.parameters else {
        return 0;
    };
    let raw = params.data;
    SHA2.iter()
        .find(|(oid, _)| raw.windows(oid.len()).any(|w| w == oid))
        .map_or(0, |(_, value)| *value)
}

/// A URI as Go's `url.URL` encodes it.
fn go_url(uri: &str) -> Json {
    let (scheme, rest) = uri.split_once(':').unwrap_or(("", uri));
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (host, path) = match rest.strip_prefix("//") {
        Some(authority) => match authority.find('/') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        },
        None => ("", rest),
    };
    json!({
        "Scheme": scheme, "Opaque": "", "User": null, "Host": host, "Path": path,
        "RawPath": "", "OmitHost": false, "ForceQuery": false, "RawQuery": query,
        "Fragment": fragment, "RawFragment": "",
    })
}

/// An OID as Go's `asn1.ObjectIdentifier` encodes it: an array of ints.
fn oid_json(oid: &Oid<'_>) -> Json {
    oid.iter().map_or(Json::Null, |arcs| {
        arcs.map(Json::from).collect::<Vec<_>>().into()
    })
}

/// RFC 3339 in UTC, as Go formats a parsed certificate's times.
fn rfc3339(timestamp: i64) -> Json {
    chrono::DateTime::from_timestamp(timestamp, 0).map_or(Json::Null, |t| {
        t.format("%Y-%m-%dT%H:%M:%SZ").to_string().into()
    })
}

/// Go encodes a nil slice as null: absent fields are null, not `[]`.
fn or_null(items: Vec<Json>) -> Json {
    if items.is_empty() {
        Json::Null
    } else {
        items.into()
    }
}

#[cfg(test)]
mod tests {
    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    // The certificate from Kyverno's tests.
    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIC7TCCAdWgAwIBAgIBADANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA0qLmt5
dmVybm8uc3ZjMB4XDTIyMTAxMDExNDYzMloXDTIzMTAxMDEyNDYzMlowGDEWMBQG
A1UEAwwNKi5reXZlcm5vLnN2YzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOKF+2P0Ufp855hpdsGD4lYkd6oU7HZAOWm1XskAMwrdsqWwTNNAinyHRoPQ
IbNbGDQ+r6Cggc2mlxHJ90PnC2weHj5otaD17Z+ARZpJZ4HMWkEfFt8sxwo9vuQJ
RWihqNwFheowjswoSB1DHnPufrZHfztkMoRx278ZfHaIMdlSTg50ektkNDoHA3OJ
sxxw54X3HR1iq6SZwN8xNT0TI6B6BbfAYWMNmKCiZ2iV6kW//XnTEqGd2WcmhuP0
SjwO4tCJbj9oV6+Bj/uhFr7J4foErMaodYDBtQs/ul2tcAwSBHfnC2KcLbiZTZsC
0Rs0WPJ4YwF/cOsD7Z/RmLs4FHsCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgKkMA8G
A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFJaK+3Wfnf7rVkYBzMCLSaV56NMqMA0G
CSqGSIb3DQEBCwUAA4IBAQDY7F6b+t9BX7098JyGk6zeT39MoLdSv+8IaKXn+m8G
yOKn3CZkruko57ycvPd4taC0gggtmUYynFhwPMQr+boNrrK9rat8Jw3yPPsBq/8D
/s6tvwxSNXBfPUI5OvNIB/hA5XpJpdHQaCkYm+FWkcJsolkkbSOfVjUjImW26JHB
nnPPtR4Y7dx0SVoPS19IC0T5RmdvgqlXj4XbhTnX3QOujVHn8u+wQ8po7EngHDQs
+onfkp8ipe0QpEJL1ZdW2LhyDXGKrZ2y8UPZ9wYNzxHWaj1Thu4B9YFdsPUwWqSx
n9e+FygpoktlD8YgT7jwgiVKX7Koz++zyvMIdhvRrtgS
-----END CERTIFICATE-----";

    // The same assertions as Kyverno's test.
    #[test]
    fn decodes_a_certificate() {
        let decoded = format!("x509.decode('''{CERT}''')");
        for check in [
            "c.IsCA && c.BasicConstraintsValid && !c.MaxPathLenZero",
            "c.KeyUsage == 37 && c.SerialNumber == 0 && c.PublicKeyAlgorithm == 1",
            "c.MaxPathLen == -1",
            "c.NotBefore == '2022-10-10T11:46:32Z' && c.NotAfter == '2023-10-10T12:46:32Z'",
            "c.Issuer.CommonName == '*.kyverno.svc' && c.Issuer.SerialNumber == ''",
            "c.PublicKey.E == 65537 && c.PublicKey.N.startsWith('28595925905962223424')",
            "size(c.Extensions) == 3 && c.Extensions[0].Critical",
        ] {
            let expr = format!("[{decoded}].all(c, {check})");
            assert_eq!(eval(&expr), Ok(Value::Bool(true)), "{check}");
        }
    }

    #[test]
    fn rejects_invalid_pem() {
        assert!(eval("x509.decode('not a valid PEM')").is_err());
    }
}
