//! Which delivery service `HttpMlsDsIdentityResolver` binds an account's push
//! keys to, with the PLC directory and the account's PDS played by local mock
//! servers and requests sent through the gateway's real hardened client.

use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

use super::gateway::{
    declaration_delivery_services, DeliveryServiceSource, HttpMlsDsIdentityResolver,
    MlsDsIdentityResolver, UserDeliveryService, UserDeliveryServiceError,
};

const ACCOUNT: &str = "did:plc:simjzkp2kphgi6zutwqxhyzm";
const CATBIRD_DS: &str = "did:web:chat.catbird.blue";
const OTHER_DS: &str = "did:web:mls.bob-home.org";
const GET_RECORD: &str = "/xrpc/com.atproto.repo.getRecord";

struct World {
    plc: MockServer,
    pds: MockServer,
}

impl World {
    async fn start() -> Self {
        Self {
            plc: MockServer::start().await,
            pds: MockServer::start().await,
        }
    }

    /// A resolver whose chat-declaration fallback accepts only `CATBIRD_DS`.
    fn resolver(&self) -> HttpMlsDsIdentityResolver {
        self.resolver_allowing(vec![CATBIRD_DS.to_string()])
    }

    fn resolver_allowing(&self, allowed: Vec<String>) -> HttpMlsDsIdentityResolver {
        HttpMlsDsIdentityResolver::new(
            crate::services::build_hardened_raw_http_client().expect("hardened client"),
            self.plc.uri(),
        )
        .with_declaration_fallback(allowed)
    }

    fn pds_service(&self) -> Value {
        json!({
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": self.pds.uri(),
        })
    }

    async fn serve_did_document(&self, services: Value) {
        Mock::given(method("GET"))
            .and(path(format!("/{ACCOUNT}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "id": ACCOUNT, "service": services })),
            )
            .mount(&self.plc)
            .await;
    }

    async fn serve_get_record(&self, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(GET_RECORD))
            .and(query_param("repo", ACCOUNT))
            .and(query_param("collection", "blue.catbird.chat.declaration"))
            .and(query_param("rkey", "self"))
            .respond_with(response)
            .mount(&self.pds)
            .await;
    }

    async fn pds_requests(&self) -> Vec<wiremock::Request> {
        self.pds.received_requests().await.unwrap_or_default()
    }
}

fn mls_service(endpoint: Value) -> Value {
    json!({
        "id": "#atproto_mls",
        "type": "AtprotoMLSDeliveryService",
        "serviceEndpoint": endpoint,
    })
}

fn declaration(delivery_service: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "uri": format!("at://{ACCOUNT}/blue.catbird.chat.declaration/self"),
        "cid": "bafyreieuuyuwepk4j7aqlkkxmzfw3g7fomuet72brmcewpnzh4o6dz2coq",
        "value": {
            "$type": "blue.catbird.chat.declaration",
            "createdAt": "2026-09-03T08:40:20.910Z",
            "allowIncoming": "all",
            "deliveryService": delivery_service,
            "protocolVersion": "2",
        },
    }))
}

fn from_declaration(did: &str) -> UserDeliveryService {
    UserDeliveryService {
        did: did.to_string(),
        source: DeliveryServiceSource::ChatDeclaration,
    }
}

fn from_did_document(did: &str) -> UserDeliveryService {
    UserDeliveryService {
        did: did.to_string(),
        source: DeliveryServiceSource::DidDocument,
    }
}

#[tokio::test]
async fn a_did_document_entry_is_used_and_the_declaration_is_never_read() {
    let world = World::start().await;
    world
        .serve_did_document(json!([
            world.pds_service(),
            mls_service(json!("https://mls.bob-home.org"))
        ]))
        .await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert_eq!(resolved, Ok(from_did_document(OTHER_DS)));
    assert!(world.pds_requests().await.is_empty());
}

#[tokio::test]
async fn a_declaration_alone_binds_its_delivery_service() {
    let world = World::start().await;
    world.serve_did_document(json!([world.pds_service()])).await;
    world.serve_get_record(declaration(CATBIRD_DS)).await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert_eq!(resolved, Ok(from_declaration(CATBIRD_DS)));
    // One public read, carrying nothing that identifies or authorizes anyone.
    let requests = world.pds_requests().await;
    assert_eq!(requests.len(), 1);
    for header in ["authorization", "cookie", "dpop", "atproto-proxy"] {
        assert!(
            !requests[0].headers.contains_key(header),
            "the declaration read must not send '{header}'"
        );
    }
}

#[tokio::test]
async fn when_both_exist_and_disagree_the_did_document_wins() {
    let world = World::start().await;
    world
        .serve_did_document(json!([
            world.pds_service(),
            mls_service(json!("did:web:mls.bob-home.org#atproto_mls"))
        ]))
        .await;
    // The declaration names the allowlisted service; it still must not win.
    world.serve_get_record(declaration(CATBIRD_DS)).await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert_eq!(resolved, Ok(from_did_document(OTHER_DS)));
    assert!(
        world.pds_requests().await.is_empty(),
        "a DID-document entry must end the lookup before the PDS is asked"
    );
}

#[tokio::test]
async fn a_malformed_did_document_entry_fails_instead_of_falling_back() {
    let world = World::start().await;
    world
        .serve_did_document(json!([
            world.pds_service(),
            mls_service(json!({ "uri": "https://mls.bob-home.org" }))
        ]))
        .await;
    world.serve_get_record(declaration(CATBIRD_DS)).await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert!(
        matches!(resolved, Err(UserDeliveryServiceError::Invalid(_))),
        "{resolved:?}"
    );
    assert!(world.pds_requests().await.is_empty());
}

#[tokio::test]
async fn neither_source_is_not_declared() {
    let world = World::start().await;
    world.serve_did_document(json!([world.pds_service()])).await;
    world
        .serve_get_record(ResponseTemplate::new(400).set_body_json(json!({
            "error": "RecordNotFound",
            "message": format!(
                "Could not locate record: at://{ACCOUNT}/blue.catbird.chat.declaration/self"
            ),
        })))
        .await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert_eq!(resolved, Err(UserDeliveryServiceError::NotDeclared));
}

#[tokio::test]
async fn a_did_document_with_no_pds_and_no_entry_is_refused() {
    let world = World::start().await;
    world.serve_did_document(json!([])).await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert!(
        matches!(resolved, Err(UserDeliveryServiceError::Invalid(_))),
        "{resolved:?}"
    );
}

#[tokio::test]
async fn a_malformed_declaration_is_invalid() {
    let bodies = [
        // No delivery service.
        json!({
            "uri": format!("at://{ACCOUNT}/blue.catbird.chat.declaration/self"),
            "value": {
                "$type": "blue.catbird.chat.declaration",
                "createdAt": "2026-09-03T08:40:20.910Z",
                "allowIncoming": "all",
                "protocolVersion": "2",
            },
        }),
        // A different account's record.
        json!({
            "uri": "at://did:plc:6u6rzv6fk3ga37kgs3tybgdk/blue.catbird.chat.declaration/self",
            "value": {
                "$type": "blue.catbird.chat.declaration",
                "createdAt": "2026-09-03T08:40:20.910Z",
                "allowIncoming": "all",
                "deliveryService": CATBIRD_DS,
                "protocolVersion": "2",
            },
        }),
        json!("did:web:chat.catbird.blue"),
    ];
    for body in bodies {
        let world = World::start().await;
        world.serve_did_document(json!([world.pds_service()])).await;
        world
            .serve_get_record(ResponseTemplate::new(200).set_body_json(&body))
            .await;

        let resolved = world
            .resolver()
            .resolve_user_push_delivery_service(ACCOUNT)
            .await;

        assert!(
            matches!(resolved, Err(UserDeliveryServiceError::Invalid(_))),
            "{body} gave {resolved:?}"
        );
    }
}

#[tokio::test]
async fn an_unreachable_pds_is_unavailable() {
    // A port nothing listens on.
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let world = World::start().await;
    world
        .serve_did_document(json!([{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": format!("http://127.0.0.1:{closed_port}"),
        }]))
        .await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert!(
        matches!(resolved, Err(UserDeliveryServiceError::Unavailable(_))),
        "{resolved:?}"
    );
}

#[tokio::test]
async fn a_failing_pds_is_unavailable_never_absent() {
    let answers = [
        ResponseTemplate::new(503).set_body_string("upstream down"),
        ResponseTemplate::new(500).set_body_json(json!({ "error": "RecordNotFound" })),
        ResponseTemplate::new(401).set_body_json(json!({ "error": "AuthRequired" })),
        ResponseTemplate::new(400)
            .set_body_json(json!({ "error": "InvalidRequest", "message": "Could not find repo" })),
        ResponseTemplate::new(404).set_body_string("<html>404</html>"),
    ];
    for answer in answers {
        let world = World::start().await;
        world.serve_did_document(json!([world.pds_service()])).await;
        world.serve_get_record(answer).await;

        let resolved = world
            .resolver()
            .resolve_user_push_delivery_service(ACCOUNT)
            .await;

        assert!(
            matches!(resolved, Err(UserDeliveryServiceError::Unavailable(_))),
            "{resolved:?}"
        );
    }
}

#[tokio::test]
async fn a_failing_directory_is_unavailable() {
    // Every answer here can change on its own, so the client should retry.
    for status in [500, 502, 503, 504, 429, 408, 403, 400] {
        let world = World::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{ACCOUNT}")))
            .respond_with(ResponseTemplate::new(status))
            .mount(&world.plc)
            .await;

        let resolved = world
            .resolver()
            .resolve_user_push_delivery_service(ACCOUNT)
            .await;

        assert!(
            matches!(resolved, Err(UserDeliveryServiceError::Unavailable(_))),
            "HTTP {status}: {resolved:?}"
        );
    }
}

#[tokio::test]
async fn an_unreachable_directory_is_unavailable() {
    // A port nothing listens on.
    let closed_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let resolver = HttpMlsDsIdentityResolver::new(
        crate::services::build_hardened_raw_http_client().expect("hardened client"),
        format!("http://127.0.0.1:{closed_port}"),
    )
    .with_declaration_fallback(vec![CATBIRD_DS.to_string()]);

    let resolved = resolver.resolve_user_push_delivery_service(ACCOUNT).await;

    assert!(
        matches!(resolved, Err(UserDeliveryServiceError::Unavailable(_))),
        "{resolved:?}"
    );
}

#[tokio::test]
async fn a_refused_directory_address_is_unavailable() {
    // The directory address is this gateway's configuration, not the account's.
    let resolver = HttpMlsDsIdentityResolver::new(
        crate::services::build_hardened_raw_http_client().expect("hardened client"),
        "http://10.0.0.1".to_string(),
    )
    .with_declaration_fallback(vec![CATBIRD_DS.to_string()]);

    let resolved = resolver.resolve_user_push_delivery_service(ACCOUNT).await;

    assert!(
        matches!(resolved, Err(UserDeliveryServiceError::Unavailable(_))),
        "{resolved:?}"
    );
}

#[tokio::test]
async fn a_did_the_directory_does_not_have_is_unresolvable() {
    // 404: never registered. 410: tombstoned. Neither changes on retry.
    for status in [404, 410] {
        let world = World::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{ACCOUNT}")))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({ "message": format!("DID not registered: {ACCOUNT}") })),
            )
            .mount(&world.plc)
            .await;

        let resolved = world
            .resolver()
            .resolve_user_push_delivery_service(ACCOUNT)
            .await;

        assert!(
            matches!(resolved, Err(UserDeliveryServiceError::Unresolvable(_))),
            "HTTP {status}: {resolved:?}"
        );
        assert!(world.pds_requests().await.is_empty());
    }
}

#[tokio::test]
async fn a_did_that_can_never_be_looked_up_is_unresolvable() {
    let unusable = [
        // Not a method this gateway resolves.
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "did:example:alice",
        "not-a-did",
        // Not a PLC identifier: wrong length, wrong alphabet.
        "did:plc:tooshort",
        "did:plc:SIMJZKP2KPHGI6ZUTWQXHYZM",
        // did:web with no host, or a path that could leave its directory.
        "did:web:",
        "did:web:example.com:..:did.json",
        "did:web:example.com::users",
        // did:web on an address the gateway refuses to contact.
        "did:web:10.0.0.1",
        "did:web:169.254.169.254",
    ];
    let world = World::start().await;
    for did in unusable {
        let resolved = world
            .resolver()
            .resolve_user_push_delivery_service(did)
            .await;

        assert!(
            matches!(resolved, Err(UserDeliveryServiceError::Unresolvable(_))),
            "{did}: {resolved:?}"
        );
    }
    assert!(
        world
            .plc
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "none of these may reach the directory"
    );
}

#[tokio::test]
async fn an_oversized_did_document_is_unresolvable() {
    let world = World::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{ACCOUNT}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; 256 * 1024 + 1]))
        .mount(&world.plc)
        .await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert!(
        matches!(resolved, Err(UserDeliveryServiceError::Unresolvable(_))),
        "{resolved:?}"
    );
}

#[tokio::test]
async fn the_did_document_only_lookup_reports_the_same_failures_as_before() {
    // `getServiceAuth` uses this lookup; its error text is unchanged.
    let world = World::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{ACCOUNT}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&world.plc)
        .await;
    let resolver = world.resolver();

    let missing = resolver
        .resolve_user_mls_service_did(ACCOUNT)
        .await
        .expect_err("a 404 is an error");
    assert_eq!(
        missing.to_string(),
        format!("DID document lookup for {ACCOUNT} returned HTTP 404 Not Found")
    );

    let unsupported = resolver
        .resolve_user_mls_service_did("did:example:alice")
        .await
        .expect_err("an unsupported method is an error");
    assert_eq!(
        unsupported.to_string(),
        "unsupported DID method 'did:example:alice'"
    );
}

#[tokio::test]
async fn a_redirect_from_the_pds_is_not_followed() {
    let world = World::start().await;
    let elsewhere = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(declaration(CATBIRD_DS))
        .mount(&elsewhere)
        .await;
    world.serve_did_document(json!([world.pds_service()])).await;
    world
        .serve_get_record(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}{GET_RECORD}", elsewhere.uri())),
        )
        .await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert!(
        matches!(resolved, Err(UserDeliveryServiceError::Unavailable(_))),
        "{resolved:?}"
    );
    assert!(
        elsewhere
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the redirect target must never be contacted"
    );
}

#[tokio::test]
async fn an_oversized_answer_is_unavailable() {
    let world = World::start().await;
    world.serve_did_document(json!([world.pds_service()])).await;
    world
        .serve_get_record(ResponseTemplate::new(200).set_body_bytes(vec![b' '; 64 * 1024 + 1]))
        .await;

    let resolved = world
        .resolver()
        .resolve_user_push_delivery_service(ACCOUNT)
        .await;

    assert!(
        matches!(resolved, Err(UserDeliveryServiceError::Unavailable(_))),
        "{resolved:?}"
    );
}

#[tokio::test]
async fn a_declared_service_off_the_allowlist_is_refused_and_not_remembered() {
    let world = World::start().await;
    world.serve_did_document(json!([world.pds_service()])).await;
    world.serve_get_record(declaration(OTHER_DS)).await;
    let resolver = world.resolver();

    for _ in 0..2 {
        assert_eq!(
            resolver.resolve_user_push_delivery_service(ACCOUNT).await,
            Err(UserDeliveryServiceError::NotAllowed(OTHER_DS.to_string()))
        );
    }
    assert_eq!(
        world.pds_requests().await.len(),
        2,
        "a refused answer must not be cached"
    );

    // An operator who lists that service accepts the same record.
    assert_eq!(
        world
            .resolver_allowing(vec![CATBIRD_DS.to_string(), OTHER_DS.to_string()])
            .resolve_user_push_delivery_service(ACCOUNT)
            .await,
        Ok(from_declaration(OTHER_DS))
    );
}

#[tokio::test]
async fn with_no_allowlist_the_declaration_is_never_read() {
    let world = World::start().await;
    world.serve_did_document(json!([world.pds_service()])).await;
    world.serve_get_record(declaration(CATBIRD_DS)).await;

    // An empty allowlist, and a resolver that was never given one.
    let unconfigured = HttpMlsDsIdentityResolver::new(
        crate::services::build_hardened_raw_http_client().unwrap(),
        world.plc.uri(),
    );
    for resolver in [world.resolver_allowing(Vec::new()), unconfigured] {
        assert_eq!(
            resolver.resolve_user_push_delivery_service(ACCOUNT).await,
            Err(UserDeliveryServiceError::NotDeclared)
        );
    }
    assert!(world.pds_requests().await.is_empty());
}

#[tokio::test]
async fn an_accepted_declaration_is_cached_and_never_reaches_service_auth() {
    let world = World::start().await;
    world.serve_did_document(json!([world.pds_service()])).await;
    world.serve_get_record(declaration(CATBIRD_DS)).await;
    let resolver = world.resolver();

    for _ in 0..3 {
        assert_eq!(
            resolver.resolve_user_push_delivery_service(ACCOUNT).await,
            Ok(from_declaration(CATBIRD_DS))
        );
    }
    assert_eq!(world.pds_requests().await.len(), 1);

    // `getServiceAuth` decides token audiences with the DID-document lookup.
    // A declaration must not widen it, even once one has been accepted for push.
    let for_service_auth = resolver.resolve_user_mls_service_did(ACCOUNT).await;
    assert!(
        for_service_auth.is_err(),
        "the DID-document lookup must stay DID-document only, got {for_service_auth:?}"
    );
}

#[test]
fn the_allowlist_defaults_to_the_gateways_own_delivery_service() {
    let own = Some("did:web:chat.catbird.blue#atproto_mls");
    assert_eq!(declaration_delivery_services(None, own), [CATBIRD_DS]);
    assert!(declaration_delivery_services(None, None).is_empty());

    // The environment replaces the default; set-but-empty turns the fallback off.
    assert_eq!(
        declaration_delivery_services(
            Some(" did:web:mls.bob-home.org , did:web:chat.catbird.blue,,did:web:mls.bob-home.org"),
            own
        ),
        [OTHER_DS, CATBIRD_DS]
    );
    assert!(declaration_delivery_services(Some(""), own).is_empty());
    assert!(declaration_delivery_services(Some(" , "), own).is_empty());

    // Entries that are not plain supported DIDs never widen the list.
    assert_eq!(
        declaration_delivery_services(
            Some("*,https://chat.catbird.blue,did:web:localhost,did:web:chat.catbird.blue"),
            None
        ),
        [CATBIRD_DS]
    );
}
