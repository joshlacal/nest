//! Synthetic contract tests for the real cleanup coordinator. These do not
//! exercise the production HTTP/SQL/Redis adapters or contact an OAuth provider.
use std::{collections::{BTreeSet,HashMap,VecDeque},sync::{Arc,Mutex}};
use async_trait::async_trait;
use catbird::services::{logout_cleanup::*,push::registry::session_fingerprint,revocation::RevokeOutcome};
use jacquard_oauth::session::ClientSessionData;
use uuid::Uuid;
#[path="support/cleanup_auth.rs"] mod fixture;

const DID:&str="did:plc:syntheticcleanup";
#[derive(Default)]
struct State {
    live:BTreeSet<String>, receipts:HashMap<String,CleanupJournal>,
    events:Vec<&'static str>, checkpoints:usize, fail_checkpoint:Option<usize>, fail_retirement:bool,
    device_results:VecDeque<Result<(),WorkFailure>>, erase_results:VecDeque<Result<(),WorkFailure>>,
    revoke_results:VecDeque<RevokeOutcome>, grant_deleted:usize, released:usize,
    revoke_never_finishes:bool,
}
#[derive(Clone)] struct Fake { state:Arc<Mutex<State>> }
impl Fake {
    fn new(bearers:&[&str])->Self {
        let mut state=State::default(); state.live=bearers.iter().map(|id|id.to_string()).collect();
        Self {state:Arc::new(Mutex::new(state))}
    }
    fn stored(&self,request:&LogoutRequest)->CleanupJournal {self.state.lock().unwrap().receipts[&request.bearer].clone()}
}
#[async_trait]
impl CleanupStore for Fake {
    async fn begin_or_resume(&self,request:&LogoutRequest,now:i64)->Result<CleanupAttempt,CleanupError> {
        request.retention.validate()?;
        let mut s=self.state.lock().unwrap();
        if let Some(journal)=s.receipts.get(&request.bearer).cloned() {
            if journal.retention!=request.retention {return Err(CleanupError::ReceiptConflict)}
            let grant=if journal.retained_credential {Some(fixture::grant(DID,&request.bearer,"https://synthetic.invalid"))}else{None};
            s.events.push("resume"); return Ok(CleanupAttempt {journal,grant})
        }
        if !s.live.contains(&request.bearer) {return Err(CleanupError::Unauthorized)}
        if s.fail_retirement {return Err(CleanupError::StorageUnavailable)}
        s.events.push("intent_and_retire");s.live.remove(&request.bearer);
        let last=s.live.is_empty();
        let seconds=match request.retention {CredentialRetention::Forbidden=>0,CredentialRetention::ApprovedSealedRetry {seconds}=>seconds};
        let journal=CleanupJournal {
            receipt_id:Uuid::new_v4(),target:CleanupTarget {did:DID.into(),session_hmac:session_fingerprint(&request.bearer),
                session_fingerprint:session_fingerprint(&request.bearer),device_ids:vec![Uuid::new_v4(),Uuid::new_v4()]},
            retention:request.retention,created_at:now,credential_expires_at:if seconds>0 {Some(now+i64::from(seconds))} else {None},
            device_cleanup:WorkStatus::Pending,account_cleanup:AccountCleanupStatus {required:last,status:if last {WorkStatus::Pending}else{WorkStatus::NotRequired}},
            upstream_revocation:UpstreamStatus::Pending,revocation_attempts:0,retained_credential:seconds>0,fence_released:!last,revision:0,
        };
        s.receipts.insert(request.bearer.clone(),journal.clone());
        Ok(CleanupAttempt {journal,grant:Some(fixture::grant(DID,&request.bearer,"https://synthetic.invalid"))})
    }
    async fn checkpoint(&self,journal:&mut CleanupJournal)->Result<(),CleanupError> {
        let mut s=self.state.lock().unwrap();s.checkpoints+=1;s.events.push("checkpoint");
        if s.fail_checkpoint==Some(s.checkpoints) {return Err(CleanupError::StorageUnavailable)}
        let stored=s.receipts.values_mut().find(|j|j.receipt_id==journal.receipt_id).ok_or(CleanupError::ReceiptConflict)?;
        if stored.revision!=journal.revision {return Err(CleanupError::ReceiptConflict)}
        journal.revision+=1;*stored=journal.clone();Ok(())
    }
    async fn delete_retained_grant(&self,_:&CleanupTarget)->Result<(),CleanupError> {
        let mut s=self.state.lock().unwrap();s.events.push("delete_grant");s.grant_deleted+=1;Ok(())
    }
    async fn release_fence(&self,_:&CleanupJournal)->Result<(),CleanupError> {
        let mut s=self.state.lock().unwrap();s.events.push("release_fence");s.released+=1;Ok(())
    }
}
#[async_trait]
impl CleanupEffects for Fake {
    async fn stop_devices(&self,target:&CleanupTarget)->Result<(),WorkFailure> {
        let mut s=self.state.lock().unwrap();assert!(s.live.iter().all(|id|session_fingerprint(id)!=target.session_fingerprint));
        s.events.push("stop_devices");s.device_results.pop_front().unwrap_or(Ok(()))
    }
    async fn erase_account(&self,_:&CleanupTarget,_:Uuid)->Result<(),WorkFailure> {
        let mut s=self.state.lock().unwrap();assert!(s.live.is_empty());s.events.push("erase_account");s.erase_results.pop_front().unwrap_or(Ok(()))
    }
    async fn revoke(&self,grant:&mut ClientSessionData,_:Uuid)->RevokeOutcome {
        let (never_finishes,outcome) = {
            let mut s=self.state.lock().unwrap();assert!(!s.live.contains(grant.session_id.as_str()));assert!(s.live.is_empty());
            assert!(s.receipts.values().any(|j|j.revocation_attempts>0),"attempt budget must persist before provider call");
            s.events.push("revoke");
            (s.revoke_never_finishes,s.revoke_results.pop_front().unwrap_or(RevokeOutcome::Revoked))
        };
        if never_finishes {
            with_revocation_deadline(std::future::pending::<RevokeOutcome>(),std::time::Duration::from_millis(1)).await
        } else {outcome}
    }
}
fn request(policy:CredentialRetention)->LogoutRequest {LogoutRequest::new(Uuid::new_v4().to_string(),policy).unwrap()}
#[test]
fn generic_policy_is_explicit_and_hard_bounded() {
    assert!(CredentialRetention::ApprovedSealedRetry {seconds:0}.validate().is_err());
    assert!(CredentialRetention::ApprovedSealedRetry {seconds:604801}.validate().is_err());
    assert_eq!(CredentialRetention::Forbidden.validate().unwrap(),CredentialRetention::Forbidden);
    assert!(LogoutRequest::new("arbitrary-did-or-receipt".into(),CredentialRetention::Forbidden).is_err());
}
#[test]
fn runtime_policy_is_fixed_forbidden_without_environment_input() {
    // There is no environment-setting argument or lookup in this runtime policy.
    assert_eq!(runtime_credential_retention(),CredentialRetention::Forbidden);
    let request=LogoutRequest::for_runtime(Uuid::new_v4().to_string()).unwrap();
    assert_eq!(request.retention,CredentialRetention::Forbidden);
}

#[tokio::test]
async fn last_session_retirement_precedes_all_effects_and_duplicate_is_idempotent() {
    let r=request(CredentialRetention::Forbidden);let f=Fake::new(&[&r.bearer]);
    let response=run_cleanup(&f,&f,&r,100).await.unwrap();assert_eq!(response.completion,Completion::Complete);
    assert_eq!(response.upstream_revocation,UpstreamStatus::Revoked);assert!(response.account_cleanup.required);
    assert_eq!(f.state.lock().unwrap().events.first(),Some(&"intent_and_retire"));
    let again=run_cleanup(&f,&f,&r,101).await.unwrap();assert_eq!(again,response);
    let s=f.state.lock().unwrap();assert_eq!(s.events.iter().filter(|&&e|e=="revoke").count(),1);assert_eq!(s.released,1);
}
#[tokio::test]
async fn two_distinct_live_bearers_preserve_account_and_defer_potentially_shared_grant() {
    let a=request(CredentialRetention::Forbidden);let b=request(CredentialRetention::Forbidden);let f=Fake::new(&[&a.bearer,&b.bearer]);
    let response=run_cleanup(&f,&f,&a,100).await.unwrap();assert!(!response.account_cleanup.required);
    assert_eq!(response.account_cleanup.status,WorkStatus::NotRequired);assert_eq!(response.upstream_revocation,UpstreamStatus::Unconfirmed);
    assert_eq!(response.completion,Completion::Failed);assert!(f.state.lock().unwrap().live.contains(&b.bearer));
    assert!(!f.state.lock().unwrap().events.contains(&"revoke"));assert!(!f.state.lock().unwrap().events.contains(&"erase_account"));
    let final_response=run_cleanup(&f,&f,&b,101).await.unwrap();assert!(final_response.account_cleanup.required);
}
#[tokio::test]
async fn two_device_links_on_one_bearer_are_one_authority_and_both_retire() {
    let r=request(CredentialRetention::Forbidden);let f=Fake::new(&[&r.bearer,&r.bearer]);
    let response=run_cleanup(&f,&f,&r,100).await.unwrap();assert!(response.account_cleanup.required);
    assert_eq!(f.stored(&r).target.device_ids.len(),2);assert!(f.state.lock().unwrap().live.is_empty());
}
#[tokio::test]
async fn retirement_storage_failure_runs_no_effects() {
    let r=request(CredentialRetention::Forbidden);let f=Fake::new(&[&r.bearer]);f.state.lock().unwrap().fail_retirement=true;
    assert_eq!(run_cleanup(&f,&f,&r,100).await.unwrap_err(),CleanupError::StorageUnavailable);
    let s=f.state.lock().unwrap();assert!(s.live.contains(&r.bearer));assert!(s.events.is_empty());
}
#[tokio::test]
async fn checkpoint_failure_after_retirement_never_reports_complete() {
    let r=request(CredentialRetention::Forbidden);let f=Fake::new(&[&r.bearer]);f.state.lock().unwrap().fail_checkpoint=Some(1);
    assert_eq!(run_cleanup(&f,&f,&r,100).await.unwrap_err(),CleanupError::StorageUnavailable);
    assert!(!f.state.lock().unwrap().live.contains(&r.bearer));assert_eq!(f.stored(&r).device_cleanup,WorkStatus::Pending);
    f.state.lock().unwrap().fail_checkpoint=None;
    let resumed=run_cleanup(&f,&f,&r,101).await.unwrap();assert_eq!(resumed.upstream_revocation,UpstreamStatus::Unconfirmed);
    assert_eq!(resumed.account_cleanup.status,WorkStatus::Complete);assert_eq!(resumed.completion,Completion::Failed);
}
#[tokio::test]
async fn forbidden_retention_reports_failed_provider_without_persisting_retry_credentials() {
    let r=request(CredentialRetention::Forbidden);let f=Fake::new(&[&r.bearer]);f.state.lock().unwrap().revoke_results.push_back(RevokeOutcome::Failed("synthetic".into()));
    let response=run_cleanup(&f,&f,&r,100).await.unwrap();assert_eq!(response.upstream_revocation,UpstreamStatus::Unconfirmed);
    assert_eq!(response.completion,Completion::Failed);assert!(!f.stored(&r).retained_credential);assert_eq!(f.state.lock().unwrap().grant_deleted,0);
}
#[tokio::test]
async fn explicit_retention_retries_after_retirement_and_deletes_secret_only_after_checkpoint() {
    let r=request(CredentialRetention::ApprovedSealedRetry {seconds:600});let f=Fake::new(&[&r.bearer]);
    f.state.lock().unwrap().revoke_results.push_back(RevokeOutcome::Failed("synthetic".into()));
    let pending=run_cleanup(&f,&f,&r,100).await.unwrap();assert_eq!(pending.completion,Completion::Pending);assert!(f.stored(&r).retained_credential);
    assert_eq!(f.state.lock().unwrap().released,0,"provider retry must retain exclusive grant fence");
    let complete=run_cleanup(&f,&f,&r,400).await.unwrap();assert_eq!(complete.completion,Completion::Complete);assert_eq!(f.state.lock().unwrap().grant_deleted,1);
    let s=f.state.lock().unwrap();let deletion=s.events.iter().position(|&e|e=="delete_grant").unwrap();assert_eq!(s.events[deletion-1],"checkpoint");
}
#[tokio::test]
async fn expired_retry_credential_is_destroyed_without_another_provider_call() {
    let r=request(CredentialRetention::ApprovedSealedRetry {seconds:10});let f=Fake::new(&[&r.bearer]);f.state.lock().unwrap().revoke_results.push_back(RevokeOutcome::Failed("synthetic".into()));
    run_cleanup(&f,&f,&r,100).await.unwrap();let response=run_cleanup(&f,&f,&r,110).await.unwrap();
    assert_eq!(response.upstream_revocation,UpstreamStatus::Unconfirmed);assert_eq!(f.state.lock().unwrap().events.iter().filter(|&&e|e=="revoke").count(),1);
    assert_eq!(f.state.lock().unwrap().grant_deleted,1);
}
#[tokio::test]
async fn sql_or_device_cleanup_failure_is_resumable_from_retired_receipt() {
    let r=request(CredentialRetention::Forbidden);let f=Fake::new(&[&r.bearer]);f.state.lock().unwrap().erase_results.push_back(Err(WorkFailure::Retryable));
    assert_eq!(run_cleanup(&f,&f,&r,100).await.unwrap().completion,Completion::Pending);
    assert_eq!(run_cleanup(&f,&f,&r,101).await.unwrap().completion,Completion::Complete);
    assert_eq!(f.state.lock().unwrap().events.iter().filter(|&&e|e=="revoke").count(),1);
}
#[tokio::test]
async fn retry_requires_same_bearer_and_same_explicit_policy() {
    let r=request(CredentialRetention::Forbidden);let f=Fake::new(&[&r.bearer]);run_cleanup(&f,&f,&r,100).await.unwrap();
    let other=request(CredentialRetention::Forbidden);assert_eq!(run_cleanup(&f,&f,&other,101).await.unwrap_err(),CleanupError::Unauthorized);
    let changed=LogoutRequest::new(r.bearer.clone(),CredentialRetention::ApprovedSealedRetry {seconds:60}).unwrap();
    assert_eq!(run_cleanup(&f,&f,&changed,101).await.unwrap_err(),CleanupError::ReceiptConflict);
    let wire=serde_json::to_string(&f.stored(&r).response()).unwrap();assert!(!wire.contains(&r.bearer));assert!(!wire.contains("synthetic-fixture-refresh"));
}
#[tokio::test]
async fn unsupported_provider_is_not_reported_revoked() {
    let r=request(CredentialRetention::Forbidden);let f=Fake::new(&[&r.bearer]);f.state.lock().unwrap().revoke_results.push_back(RevokeOutcome::NoRevocationEndpoint);
    let response=run_cleanup(&f,&f,&r,100).await.unwrap();assert_eq!(response.upstream_revocation,UpstreamStatus::Unsupported);assert_eq!(response.completion,Completion::Failed);
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn redis_concurrent_retirement_is_authoritative_and_fences_new_login() {
    use jacquard_oauth::authstore::ClientAuthStore;
    let store=fixture::store().await;
    let a=request(CredentialRetention::Forbidden);let b=request(CredentialRetention::Forbidden);
    store.upsert_session(fixture::grant(DID,&a.bearer,"https://synthetic.invalid")).await.unwrap();
    store.upsert_session(fixture::grant(DID,&b.bearer,"https://synthetic.invalid")).await.unwrap();
    let backend=RedisCleanupStore {store:&store};
    let (one,two)=tokio::join!(backend.begin_or_resume(&a,100),backend.begin_or_resume(&b,100));
    let one=one.unwrap();let two=two.unwrap();
    assert_ne!(one.journal.account_cleanup.required,two.journal.account_cleanup.required,"exactly one final-session erasure fence");
    assert!(store.read_session_local(DID,&a.bearer).await.unwrap().is_none());
    assert!(store.read_session_local(DID,&b.bearer).await.unwrap().is_none());
    let fresh=Uuid::new_v4().to_string();
    assert!(store.upsert_session(fixture::grant(DID,&fresh,"https://synthetic.invalid")).await.is_err(),"login cannot race fenced erasure");
    let final_receipt=if one.journal.account_cleanup.required {one.journal.receipt_id}else{two.journal.receipt_id};
    let mut conn=store.redis_connection();
    let fence:String=redis::cmd("GET").arg(store.account_erasure_key(DID)).query_async(&mut conn).await.unwrap();
    assert_eq!(fence,final_receipt.to_string());
    let ttl:i64=redis::cmd("TTL").arg(store.account_erasure_key(DID)).query_async(&mut conn).await.unwrap();assert_eq!(ttl,-1);
    let again=backend.begin_or_resume(&a,101).await.unwrap();assert_eq!(again.journal.receipt_id,one.journal.receipt_id);
    assert!(again.grant.is_none(),"forbidden policy never persists a bearer/grant for retry");
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn stale_device_link_cannot_be_written_after_retirement() {
    use jacquard_oauth::authstore::ClientAuthStore;
    let store=fixture::store().await;let r=request(CredentialRetention::Forbidden);
    store.upsert_session(fixture::grant(DID,&r.bearer,"https://synthetic.invalid")).await.unwrap();
    let backend=RedisCleanupStore {store:&store};backend.begin_or_resume(&r,100).await.unwrap();
    let id=Uuid::new_v4();
    assert!(catbird::services::push::session_devices::link(&store,id,&r.bearer).await.is_err());
    let mut conn=store.redis_connection();
    let exists:bool=redis::cmd("EXISTS").arg(format!("{}push_device_session:{}",store.key_prefix(),id)).query_async(&mut conn).await.unwrap();assert!(!exists);
}

#[tokio::test]
#[ignore = "requires explicit disposable Redis fixture"]
async fn unreadable_session_candidate_does_not_become_false_other_active_session() {
    use jacquard_oauth::authstore::ClientAuthStore;
    let store=fixture::store().await;let r=request(CredentialRetention::Forbidden);
    store.upsert_session(fixture::grant(DID,&r.bearer,"https://synthetic.invalid")).await.unwrap();
    let corrupt_key=format!("{}session:{}_{}",store.key_prefix(),DID,"a".repeat(64));
    let mut conn=store.redis_connection();
    let _:()=redis::cmd("SET").arg(corrupt_key).arg("not-an-authenticated-session").arg("EX").arg(600).query_async(&mut conn).await.unwrap();
    let result=RedisCleanupStore {store:&store}.begin_or_resume(&r,100).await;
    assert!(matches!(result,Err(CleanupError::InventoryIncomplete)));
    assert!(store.read_session_local(DID,&r.bearer).await.unwrap().is_some(),"ambiguity detected before destructive retirement");
}


#[tokio::test]
async fn provider_deadline_does_not_prevent_local_erasure_or_claim_revocation() {
    assert_eq!(PROVIDER_REVOKE_DEADLINE,std::time::Duration::from_secs(10));
    let r=LogoutRequest::for_runtime(Uuid::new_v4().to_string()).unwrap();
    let f=Fake::new(&[&r.bearer]);
    f.state.lock().unwrap().revoke_never_finishes=true;
    let response=run_cleanup(&f,&f,&r,100).await.unwrap();
    assert!(response.session_retired);
    assert_eq!(response.upstream_revocation,UpstreamStatus::Unconfirmed);
    assert_eq!(response.account_cleanup.status,WorkStatus::Complete);
    assert_eq!(response.completion,Completion::Failed);
    assert!(f.state.lock().unwrap().events.contains(&"erase_account"));
    assert_eq!(f.state.lock().unwrap().released,1);
    assert!(!f.stored(&r).retained_credential);
    assert_eq!(f.stored(&r).revocation_attempts,1);
}
