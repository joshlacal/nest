//! Opt-in live probe for the eMudhra intermediate compromise (October 2026).
//! Run explicitly with `cargo test --test tls_incident -- --ignored --nocapture`.
//! A generic network failure is not evidence that certificate verification worked.

use std::{error::Error, time::Duration};

use base64::Engine;
use catbird::services::build_hardened_http_client;
use hyper_rustls::HttpsConnectorBuilder;
use sha2::Digest;
use tokio::time::timeout;
use tower::Service;

fn error_chain(error: &dyn Error) -> String {
    let mut messages = Vec::new();
    let mut current = Some(error);
    while let Some(source) = current {
        messages.push(source.to_string());
        current = source.source();
    }
    messages.join(" | ")
}

fn is_certificate_failure(error: &dyn Error) -> bool {
    let message = error_chain(error).to_lowercase();
    message.contains("invalid peer certificate: revoked")
        || message.contains("invalid peer certificate: certdistrusted")
        || message.contains("invalid peer certificate: unknownissuer")
        || message.contains("unable to get local issuer certificate")
}

fn is_unknown_issuer(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(source) = current {
        if let Some(rustls_error) = source.downcast_ref::<rustls::Error>() {
            return matches!(
                rustls_error,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            );
        }
        current = source.source();
    }
    // hyper-rustls' connector can flatten rustls::Error into io::Error text.
    error_chain(error)
        .to_lowercase()
        .contains("invalid peer certificate: unknownissuer")
}

fn affected_hosts() -> Vec<String> {
    ["dv", "ov", "ev"]
        .into_iter()
        .flat_map(|class| {
            ["b", "c"].into_iter().flat_map(move |group| {
                ["", "-aaa"].into_iter().map(move |suffix| {
                    format!("{class}-g3{group}{suffix}-emudhra.we-have-a-problem.com")
                })
            })
        })
        .collect()
}

async fn verified_incident_roots() -> Vec<reqwest::Certificate> {
    const ROOTS: [(&str, &str); 4] = [
        (
            "emSign Root TLS CA - G3",
            "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D",
        ),
        (
            "emSign Root CS CA - G3",
            "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5",
        ),
        (
            "AAA Certificate Services",
            "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4",
        ),
        (
            "emSign ECC Root CA - G3",
            "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B",
        ),
    ];

    let inventory: Vec<serde_json::Value> = build_hardened_http_client()
        .expect("Nest client should build")
        .get("https://emudhra.we-have-a-problem.com/roots.json")
        .send()
        .await
        .expect("incident root inventory TLS should work")
        .error_for_status()
        .expect("incident root inventory HTTP should work")
        .json()
        .await
        .expect("incident root inventory should be JSON");

    ROOTS
        .into_iter()
        .map(|(name, expected_fingerprint)| {
            let root = inventory
                .iter()
                .find(|root| root["name"].as_str() == Some(name))
                .unwrap_or_else(|| panic!("missing incident root {name}"));
            let pem = root["pem"].as_str().expect("root PEM should be a string");
            let encoded = pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>();
            let der = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("root PEM should decode");
            let fingerprint = format!("{:X}", sha2::Sha256::digest(&der));
            assert_eq!(fingerprint, expected_fingerprint, "root {name} changed");
            reqwest::Certificate::from_der(&der).expect("root DER should parse")
        })
        .collect()
}

// a2 0.10.0 builds this connector for APNs. Incident test servers do not
// support HTTP/2, so use HTTP/1 there to reach certificate verification.
// Apple controls use a2's exact HTTP/2 setting. No HTTP request is sent.
async fn apns_connector_handshake(
    host: &str,
    http2_only: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut connector = if http2_only {
        HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http2()
            .build()
    } else {
        HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_only()
            .enable_http1()
            .build()
    };
    let uri: http::Uri = format!("https://{host}/").parse()?;
    timeout(Duration::from_secs(10), connector.call(uri)).await??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires live external incident endpoints"]
async fn proxy_and_apns_root_paths_reject_emudhra_chains() {
    let proxy = build_hardened_http_client().expect("Nest reqwest client should build");

    for host in affected_hosts() {
        let proxy_result = proxy.get(format!("https://{host}/")).send().await;
        let proxy_error = proxy_result.expect_err(&format!("Nest proxy trusted {host}"));
        println!("{host}: Nest proxy: {}", error_chain(&proxy_error));
        assert!(
            is_certificate_failure(&proxy_error),
            "Nest proxy failed {host} without a certificate error: {}",
            error_chain(&proxy_error)
        );

        let apns_result = apns_connector_handshake(&host, false).await;
        let apns_error = apns_result.expect_err(&format!("APNs root set trusted {host}"));
        println!("{host}: APNs roots: {}", error_chain(apns_error.as_ref()));
        assert!(
            is_unknown_issuer(apns_error.as_ref()),
            "APNs root set failed {host} without UnknownIssuer: {}",
            error_chain(apns_error.as_ref())
        );
    }

    proxy
        .get("https://bsky.social/")
        .send()
        .await
        .expect("Nest proxy failed normal PDS TLS control");
    apns_connector_handshake("api.push.apple.com", true)
        .await
        .expect("APNs root set failed Apple production TLS control");
    apns_connector_handshake("api.development.push.apple.com", true)
        .await
        .expect("APNs root set failed Apple sandbox TLS control");
}

#[tokio::test]
#[ignore = "requires live external incident endpoints"]
async fn patched_webpki_rejects_compromised_keys_even_if_incident_roots_are_trusted() {
    let client = reqwest::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only(verified_incident_roots().await)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("explicit-root client should build");

    for host in affected_hosts() {
        let result = client.get(format!("https://{host}/")).send().await;
        let error = result.expect_err(&format!("patched WebPKI trusted {host}"));
        let chain = error_chain(&error);
        println!("{host}: explicit incident roots: {chain}");
        assert!(
            chain.to_lowercase().contains("certdistrusted"),
            "patched WebPKI failed {host} without CertDistrusted: {chain}"
        );
    }
}
