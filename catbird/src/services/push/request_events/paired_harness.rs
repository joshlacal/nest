//! t16: a published request's wake from the real DS worker, through Nest's
//! production gateway, to the fake provider (or, once answered, nowhere).

use super::{run_paired, Scenario};

#[tokio::test]
#[ignore = "paired DS process and explicit guarded fixture required"]
async fn live_ds_worker_to_nest() {
    run_paired(
        "t16-paired-nest-",
        &[
            Scenario::RetryAfterProviderFailure,
            Scenario::CanonicalIneligible,
        ],
    )
    .await
    .unwrap();
}
