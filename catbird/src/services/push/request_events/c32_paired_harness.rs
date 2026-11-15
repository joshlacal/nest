//! C32 notification qualification: lost gateway ACK retried with stable
//! identity, close-before-push suppression, and FCM-only routing.

use super::{run_paired, Scenario};

#[tokio::test]
#[ignore = "paired DS process and explicit guarded fixture required"]
async fn live_ds_worker_to_nest_c32() {
    run_paired(
        "c32-paired-nest-",
        &[
            Scenario::ProviderAcceptedAckLost,
            Scenario::CanonicalIneligible,
            Scenario::FcmRouting,
        ],
    )
    .await
    .unwrap();
}
