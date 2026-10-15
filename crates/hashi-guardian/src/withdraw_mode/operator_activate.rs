// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator_activate`: turns a provisioner-initialized standby into the active
//! withdrawal enclave by deriving live serving state from S3 logs and checking the
//! operator-pinned `ActivationState` hash.

use crate::Enclave;
use hashi_types::guardian::ActivationState;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::OperatorActivateRequest;
use hashi_types::guardian::RateLimiter;
use hashi_types::guardian::RuntimeCommittee;
use hashi_types::guardian::WithdrawStage;
use tracing::info;
use GuardianError::InvalidInputs;

/// S3-derived activation state ready for its fail-stop commit.
///
/// Construction performs every request-dependent fallible operation without
/// mutating the enclave. Once built, the commit must either complete or abort
/// the enclave process.
struct OAInstall {
    committee: RuntimeCommittee,
    rate_limiter: RateLimiter,
    completion_log: InitLogMessage,
}

impl OAInstall {
    async fn from_request(
        enclave: &Enclave,
        request: OperatorActivateRequest,
    ) -> GuardianResult<Self> {
        let limiter_config = enclave.config.limiter_config()?;
        let initialization = enclave
            .state
            .temporary_init_state()
            .map_err(|_| InvalidInputs("temporary initialization state not set".into()))?;
        let config_hash = initialization.config_hash;
        let armed_instance = &initialization.ceremony_state.secret_sharing_instance;

        let mut reader = enclave.config.new_guardian_reader()?;

        reader
            .ensure_session_live_and_others_quiet(&enclave.config.s3_session_id())
            .await?;

        let committee = RuntimeCommittee::from_move_with_encryption_key_fallback(
            reader.read_latest_committee().await?.ok_or_else(|| {
                InvalidInputs("no committee-update or genesis record found".into())
            })?,
        )
        .map_err(|e| InvalidInputs(format!("invalid serving committee: {e}")))?;

        let limiter_state = reader.recover_limiter_state(&limiter_config).await?;
        let rate_limiter = RateLimiter::new(limiter_config, limiter_state)?;
        let sharing_seq = armed_instance.sharing_seq();
        let committee_epoch = committee.epoch();

        let activation_state = ActivationState::new(
            config_hash,
            armed_instance.clone(),
            committee.clone(),
            limiter_state,
        );
        let state_hash = activation_state.digest();
        if &state_hash != request.expected_state_hash() {
            return Err(InvalidInputs(format!(
                "ActivationState hash mismatch: expected {}, got {}",
                hex::encode(request.expected_state_hash()),
                hex::encode(state_hash)
            )));
        }

        Ok(Self {
            committee,
            rate_limiter,
            completion_log: InitLogMessage::OAActivated {
                state_hash,
                config_hash,
                sharing_seq,
                committee_epoch,
                limiter_state,
            },
        })
    }
}

pub async fn operator_activate(
    enclave: &mut Enclave,
    request: OperatorActivateRequest,
) -> GuardianResult<()> {
    info!("/operator_activate - Received request.");

    enclave.require_lifecycle(WithdrawStage::ProvisionerInitialized.into())?;
    info!("Lifecycle stage validated.");

    // ---- Validate & build: Nothing in this phase mutates enclave state, so any
    // error here leaves the enclave untouched. ----
    let install = OAInstall::from_request(enclave, request).await?;

    // ---- All-or-nothing Commit: Nothing in this phase errors out. ----
    info!("Committing committee and rate limiter.");
    commit_operator_activate(enclave, install).await;

    info!("Operator activation complete.");
    Ok(())
}

/// Install the prepared serving state, durably mark OA complete, clear stale
/// initialization inputs, and then expose the active lifecycle. This fail-stop
/// phase never returns an error after mutation begins.
async fn commit_operator_activate(enclave: &mut Enclave, install: OAInstall) {
    enclave
        .state
        .init(install.committee, install.rate_limiter)
        .expect("Unable to init activation state");

    enclave
        .log_init(install.completion_log)
        .await
        .expect("Unable to log operator activation");

    enclave.state.clear_temporary_init_state();

    enclave
        .advance_lifecycle_into(WithdrawStage::Activated.into())
        .expect("operator_activate should advance a provisioner-initialized enclave");
}

// Session attestations are Nitro-verified on read unless `non-enclave-dev` stubs them.
#[cfg(all(test, feature = "non-enclave-dev"))]
mod tests {
    use super::*;
    use crate::attestation::get_attestation;
    use crate::s3_client::GuardianS3Client;
    use crate::s3_reader::GuardianReader;
    use crate::test_utils::OperatorInitTestArgs;
    use crate::withdraw_mode::standard_withdrawal::standard_withdrawal;
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::operation::list_object_versions::ListObjectVersionsOutput;
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::primitives::ByteStream;
    use aws_sdk_s3::primitives::DateTime;
    use aws_sdk_s3::types::CommonPrefix;
    use aws_sdk_s3::types::ObjectLockMode;
    use aws_sdk_s3::types::ObjectVersion;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use bitcoin::Network;
    use hashi_types::bitcoin::BitcoinKeypair;
    use hashi_types::bitcoin::BTC_LIB;
    use hashi_types::guardian::now_timestamp_secs;
    use hashi_types::guardian::GenesisLogMessage;
    use hashi_types::guardian::GenesisState;
    use hashi_types::guardian::HashiSigned;
    use hashi_types::guardian::InitConfig;
    use hashi_types::guardian::LimiterConfig;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::LogType;
    use hashi_types::guardian::OperatorInitInfo;
    use hashi_types::guardian::OperatorInitMode;
    use hashi_types::guardian::SignedLogEntry;
    use hashi_types::guardian::SignedStandardWithdrawalRequestWire;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::WithdrawOperatorInitInfo;
    use hashi_types::guardian::WithdrawalID;
    use hashi_types::guardian::S3_DIR_WITHDRAW;
    use hpke::Serializable;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::Mutex;

    /// Key -> (body, Object Lock retain-until date).
    type Objects = Arc<Mutex<BTreeMap<String, (Vec<u8>, DateTime)>>>;

    /// A bucket that serves back what the guardians write, so each session
    /// reads earlier records through the production read path.
    #[derive(Clone, Default)]
    struct MemBucket {
        objects: Objects,
    }

    impl MemBucket {
        /// A client over this bucket. Each mock rule passes the request to its
        /// output through a Mutex, which assumes one S3 call at a time.
        fn client(&self) -> GuardianS3Client {
            let put_objects = self.objects.clone();
            let put = mock!(Client::put_object)
                .match_requests(move |req| {
                    let key = req.key().unwrap().to_string();
                    let body = req.body().bytes().unwrap().to_vec();
                    let retain_until = *req.object_lock_retain_until_date().unwrap();
                    let mut objects = put_objects.lock().unwrap();
                    assert!(!objects.contains_key(&key), "{key} written twice");
                    objects.insert(key, (body, retain_until));
                    true
                })
                .then_output(|| PutObjectOutput::builder().build());

            let dirs_prefix = Arc::new(Mutex::new(String::new()));
            let dirs_prefix_w = dirs_prefix.clone();
            let dirs_objects = self.objects.clone();
            let list_dirs = mock!(Client::list_object_versions)
                .match_requests(move |req| {
                    if req.delimiter() != Some("/") {
                        return false;
                    }
                    *dirs_prefix_w.lock().unwrap() = req.prefix().unwrap_or_default().into();
                    true
                })
                .then_output(move || {
                    let prefix = dirs_prefix.lock().unwrap().clone();
                    let children: BTreeSet<String> = dirs_objects
                        .lock()
                        .unwrap()
                        .keys()
                        .filter_map(|key| {
                            let rest = key.strip_prefix(&prefix)?;
                            let slash = rest.find('/')?;
                            Some(format!("{prefix}{}", &rest[..=slash]))
                        })
                        .collect();
                    ListObjectVersionsOutput::builder()
                        .set_common_prefixes(Some(
                            children
                                .into_iter()
                                .map(|c| CommonPrefix::builder().prefix(c).build())
                                .collect(),
                        ))
                        .build()
                });

            let keys_prefix = Arc::new(Mutex::new(String::new()));
            let keys_prefix_w = keys_prefix.clone();
            let keys_objects = self.objects.clone();
            let list_keys = mock!(Client::list_object_versions)
                .match_requests(move |req| {
                    if req.delimiter().is_some() {
                        return false;
                    }
                    *keys_prefix_w.lock().unwrap() = req.prefix().unwrap_or_default().into();
                    true
                })
                .then_output(move || {
                    let prefix = keys_prefix.lock().unwrap().clone();
                    ListObjectVersionsOutput::builder()
                        .set_versions(Some(
                            keys_objects
                                .lock()
                                .unwrap()
                                .keys()
                                .filter(|key| key.starts_with(&prefix))
                                .map(|key| {
                                    ObjectVersion::builder().key(key).is_latest(true).build()
                                })
                                .collect(),
                        ))
                        .build()
                });

            let get_key = Arc::new(Mutex::new(String::new()));
            let get_key_w = get_key.clone();
            let get_objects = self.objects.clone();
            let get = mock!(Client::get_object)
                .match_requests(move |req| {
                    *get_key_w.lock().unwrap() = req.key().unwrap().into();
                    true
                })
                .then_output(move || {
                    let key = get_key.lock().unwrap().clone();
                    let (body, retain_until) = get_objects
                        .lock()
                        .unwrap()
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| panic!("no object at {key}"));
                    GetObjectOutput::builder()
                        .object_lock_mode(ObjectLockMode::Compliance)
                        .object_lock_retain_until_date(retain_until)
                        .body(ByteStream::from(body))
                        .build()
                });

            let client = mock_client!(
                aws_sdk_s3,
                RuleMode::MatchAny,
                &[&put, &list_dirs, &list_keys, &get]
            );
            let deployment = InitConfig::mock_for_testing().deployment().clone();
            GuardianS3Client::from_client(
                deployment.bucket_info,
                deployment.retention_environment,
                client,
            )
        }

        fn withdrawal_count(&self) -> usize {
            let prefix = format!("{S3_DIR_WITHDRAW}/");
            self.objects
                .lock()
                .unwrap()
                .keys()
                .filter(|key| key.starts_with(&prefix))
                .count()
        }

        /// Drop a stopped session's heartbeats, as if they had aged out of the
        /// activation scan window after the quiet period.
        fn age_out_heartbeats(&self, session_id: &str) {
            self.objects.lock().unwrap().retain(|_, (body, _)| {
                let entry: SignedLogEntry = serde_json::from_slice(body).unwrap();
                !(entry.log_type() == LogType::Heartbeat
                    && entry.session_id().as_str() == session_id)
            });
        }
    }

    fn btc_keypair() -> bitcoin::secp256k1::Keypair {
        BitcoinKeypair::from_seckey_slice(&BTC_LIB, &[8u8; 32]).unwrap()
    }

    /// Bring a fresh session to `ProvisionerInitialized` on `bucket`. It writes
    /// the records that `operator_init` and `provisioner_init` write (genesis
    /// only at bootstrap), then one heartbeat.
    async fn provisioned_session(
        bucket: &MemBucket,
        limiter_config: LimiterConfig,
        genesis: Option<GenesisState>,
    ) -> Enclave {
        let config = InitConfig::from_parts_for_testing(limiter_config, Network::Regtest);
        let mut args = OperatorInitTestArgs::default()
            .with_s3_logger(bucket.client())
            .with_config(config.clone());
        if let Some(genesis) = genesis.clone() {
            args = args.with_genesis_state(genesis);
        }
        let mut enclave = Enclave::create_operator_initialized_with(args);

        let init = enclave.state.temporary_init_state().unwrap();
        let instance = init.ceremony_state.secret_sharing_instance.clone();
        let info = enclave.info();
        let oi_info = OperatorInitInfo {
            deployment: config.deployment().clone(),
            encryption_pubkey: enclave.config.encryption_public_key().to_bytes().to_vec(),
            mode: OperatorInitMode::Withdraw(Box::new(WithdrawOperatorInitInfo {
                secret_sharing_instance: instance.clone(),
                config_hash: init.config_hash,
                limiter_config,
                hashi_object_id: info.hashi_object_id.unwrap(),
                mpc_master_g: info.mpc_master_g.unwrap(),
                genesis_state_hash: genesis.as_ref().map(GenesisState::digest),
            })),
        };
        let signing_public_key = enclave.config.signing_pubkey();
        enclave
            .log_init(InitLogMessage::OIAttestation {
                attestation: get_attestation(&signing_public_key).unwrap(),
                signing_public_key,
            })
            .await
            .unwrap();
        enclave
            .log_init(InitLogMessage::OIGuardianInfo(Box::new(oi_info)))
            .await
            .unwrap();

        enclave.config.set_btc_keypair(btc_keypair()).unwrap();
        if let Some(genesis) = genesis {
            let (committee, hashi_object_id, mpc_master_g) = genesis.into_parts();
            enclave
                .log_genesis(GenesisLogMessage {
                    committee,
                    hashi_object_id,
                    mpc_master_g,
                })
                .await
                .unwrap();
        }
        enclave
            .log_init(InitLogMessage::PIEnclaveFullyInitialized {
                sharing_seq: instance.sharing_seq(),
                share_ids: instance
                    .commitments()
                    .iter()
                    .take(instance.threshold())
                    .map(|c| c.id)
                    .collect(),
                enclave_btc_pubkey: btc_keypair().x_only_public_key().0,
            })
            .await
            .unwrap();
        enclave
            .advance_lifecycle_into(WithdrawStage::ProvisionerInitialized.into())
            .unwrap();
        enclave.heartbeat().await.unwrap();
        enclave
    }

    /// The pin the operator derives from S3, as `hashi-guardian-init operator
    /// activate` does.
    async fn activation_pin(bucket: &MemBucket, enclave: &Enclave) -> OperatorActivateRequest {
        let mut reader = GuardianReader::from_s3_client(
            bucket.client(),
            enclave.config.deployment().unwrap().clone(),
        );
        let committee = RuntimeCommittee::from_move_with_encryption_key_fallback(
            reader.read_latest_committee().await.unwrap().unwrap(),
        )
        .unwrap();
        let limiter_state = reader
            .recover_limiter_state(&enclave.config.limiter_config().unwrap())
            .await
            .unwrap();
        let init = enclave.state.temporary_init_state().unwrap();
        OperatorActivateRequest::new(
            ActivationState::new(
                init.config_hash,
                init.ceremony_state.secret_sharing_instance.clone(),
                committee,
                limiter_state,
            )
            .digest(),
        )
    }

    async fn activated_session(
        bucket: &MemBucket,
        limiter_config: LimiterConfig,
        genesis: Option<GenesisState>,
    ) -> Enclave {
        let mut enclave = provisioned_session(bucket, limiter_config, genesis).await;
        let pin = activation_pin(bucket, &enclave).await;
        operator_activate(&mut enclave, pin)
            .await
            .expect("operator_activate succeeds");
        enclave
    }

    /// Every mock request spends the same utxos, so all have the same outflow.
    fn signed_request(seq: u64, timestamp_secs: u64) -> HashiSigned<StandardWithdrawalRequest> {
        StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0xf1; 32]),
            timestamp_secs,
            seq,
        )
        .0
    }

    fn wire(
        request: HashiSigned<StandardWithdrawalRequest>,
    ) -> SignedStandardWithdrawalRequestWire {
        let (signature, request) = request.into_parts();
        SignedStandardWithdrawalRequestWire {
            data: request.into(),
            signature: hashi_types::move_types::CommitteeSignature {
                epoch: signature.epoch(),
                signature: signature.signature_bytes().to_vec(),
                signers_bitmap: signature.signers_bitmap_bytes().to_vec(),
            },
        }
    }

    fn outflow() -> u64 {
        signed_request(0, 0)
            .message()
            .utxos()
            .gross_outflow_amount()
            .to_sat()
    }

    struct Rotated {
        bucket: MemBucket,
        new_session: Enclave,
        new_config: LimiterConfig,
        /// Timestamp of the old session's last signed withdrawal.
        last_signed_at: u64,
    }

    /// Session A (max 2 * outflow) signs one withdrawal at seq 0. The operator
    /// then stops A and activates session B with `new_max` and the same rate.
    /// The next withdrawal W, with the same outflow, is still unsigned.
    async fn rotate_after_one_withdrawal(new_max: u64) -> Rotated {
        let amount = outflow();
        // One second refills one withdrawal.
        let old_config = LimiterConfig {
            refill_rate: amount,
            max_bucket_capacity: 2 * amount,
        };
        let bucket = MemBucket::default();

        let mut old_session =
            activated_session(&bucket, old_config, Some(GenesisState::mock_for_testing())).await;
        assert_eq!(
            old_session.state.limiter_state().unwrap(),
            LimiterState::genesis(&old_config)
        );
        let last_signed_at = now_timestamp_secs() - 120;
        standard_withdrawal(&mut old_session, wire(signed_request(0, last_signed_at)))
            .await
            .expect("session A signs the withdrawal at seq 0");
        let old_state = old_session.state.limiter_state().unwrap();
        assert_eq!(old_state.next_seq, 1);
        assert_eq!(old_state.num_tokens_available, amount);

        bucket.age_out_heartbeats(&old_session.config.s3_session_id());
        drop(old_session);

        let new_config = LimiterConfig {
            max_bucket_capacity: new_max,
            ..old_config
        };
        let new_session = activated_session(&bucket, new_config, None).await;
        assert_eq!(new_session.config.limiter_config().unwrap(), new_config);
        // Recovery continues A's seq and caps A's tokens to the new max.
        assert_eq!(
            new_session.state.limiter_state().unwrap(),
            LimiterState {
                num_tokens_available: amount.min(new_max),
                last_updated_at: last_signed_at,
                next_seq: 1,
            }
        );
        Rotated {
            bucket,
            new_session,
            new_config,
            last_signed_at,
        }
    }

    /// F12: B's max is below W's outflow, so B refuses W on every attempt,
    /// even with a full bucket, and consumes no seq.
    #[tokio::test]
    async fn activation_with_max_below_committed_outflow_refuses_it_forever() {
        let amount = outflow();
        let Rotated {
            bucket,
            mut new_session,
            new_config,
            last_signed_at,
        } = rotate_after_one_withdrawal(amount - 1).await;
        assert_eq!(bucket.withdrawal_count(), 1);

        let now = now_timestamp_secs();
        // The guardian accepts timestamps up to 5 minutes ahead of its clock.
        for timestamp in [last_signed_at + 1, last_signed_at + 60, now, now + 300] {
            let state = new_session.state.limiter_state().unwrap();
            assert_eq!(
                state.capacity_at(&new_config, timestamp),
                new_config.max_bucket_capacity,
                "the bucket is full at {timestamp}"
            );
            let err = standard_withdrawal(&mut new_session, wire(signed_request(1, timestamp)))
                .await
                .unwrap_err();
            assert!(matches!(err, GuardianError::RateLimitExceeded), "{err:?}");
            assert_eq!(new_session.state.limiter_state().unwrap(), state);
        }
        assert_eq!(new_session.state.limiter_state().unwrap().next_seq, 1);
        assert_eq!(bucket.withdrawal_count(), 1);
    }

    /// Contrast: the same W is signed after a rotation whose max still covers
    /// W's outflow, including one that lowers the max to exactly that outflow.
    #[tokio::test]
    async fn activation_with_max_covering_committed_outflow_signs_it() {
        let amount = outflow();
        for new_max in [2 * amount, amount] {
            let Rotated {
                bucket,
                mut new_session,
                last_signed_at,
                ..
            } = rotate_after_one_withdrawal(new_max).await;

            standard_withdrawal(
                &mut new_session,
                wire(signed_request(1, last_signed_at + 1)),
            )
            .await
            .unwrap_or_else(|e| panic!("new max {new_max}: {e:?}"));
            assert_eq!(new_session.state.limiter_state().unwrap().next_seq, 2);
            assert_eq!(bucket.withdrawal_count(), 2);
        }
    }
}
