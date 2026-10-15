// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::LeaderService;
use super::parse_member_signature;
use crate::Hashi;
use crate::onchain::types::WithdrawalTransaction;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::SignedMessage;
use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::CommitteeTransitionRequest;
use hashi_types::guardian::GuardianSignedResponse;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::proto_conversions::signed_committee_transition_to_pb;
use hashi_types::guardian::proto_conversions::signed_standard_withdrawal_request_to_pb;
use hashi_types::proto::SignCommitteeTransitionRequest;
use hashi_types::proto::SignGuardianWithdrawalRequestRequest;
use hashi_types::proto::UpdateCommitteeChainRequest;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

impl LeaderService {
    pub(super) fn check_reconcile_guardian_committee(&mut self) {
        if self.inner.guardian_client().is_none() {
            return;
        }
        // Don't overwrite an existing handle — finished or not. The select!
        // arm clears the slot and logs the result. Letting it run first
        // avoids dropping a completed task's error on the floor.
        if self.guardian_committee_reconcile_task.is_some() {
            return;
        }
        // Only kick a reconcile when the hashi epoch advances (or on the
        // first leader tick). A no-op reconcile still costs a GetGuardianInfo
        // RPC, so don't run it every checkpoint.
        let hashi_epoch = self.inner.onchain_state().epoch();
        if self.last_guardian_reconcile_epoch == Some(hashi_epoch) {
            return;
        }
        self.last_guardian_reconcile_epoch = Some(hashi_epoch);
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move { Self::reconcile_guardian_committee(&inner).await });
        self.guardian_committee_reconcile_task = Some(AbortOnDropHandle::new(handle));
    }

    // ========================================================================
    // Guardian: post-MPC enclave-signature RPC
    // ========================================================================

    /// Returns the per-input guardian Schnorr signatures (64 bytes each)
    /// for inclusion in the on-chain `sign_withdrawal` PTB.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, seq))]
    pub(super) async fn finalize_withdrawal_through_guardian(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        members: &[CommitteeMember],
        guardian: &crate::grpc::guardian_client::GuardianClient,
        timestamp_secs: u64,
        seq: u64,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let signed_request =
            Self::collect_guardian_withdrawal_signatures(inner, txn, members, timestamp_secs, seq)
                .await?;
        let proto_request = signed_standard_withdrawal_request_to_pb(&signed_request);

        let rpc_start = std::time::Instant::now();
        let rpc_result = guardian.standard_withdrawal(proto_request).await;
        let rpc_elapsed = rpc_start.elapsed().as_secs_f64();

        let response_pb = rpc_result.map_err(|status| {
            let (rpc_outcome, retry_label) = match status.code() {
                tonic::Code::Aborted => (
                    crate::metrics::GUARDIAN_RPC_OUTCOME_SEQ_MISMATCH,
                    "GuardianSeqMismatch",
                ),
                tonic::Code::ResourceExhausted => {
                    warn!("Guardian rate-limited withdrawal, will retry later");
                    (
                        crate::metrics::GUARDIAN_RPC_OUTCOME_RATE_LIMITED,
                        "GuardianRateLimited",
                    )
                }
                _ => {
                    error!("Guardian call failed: {}", status.message());
                    (
                        crate::metrics::GUARDIAN_RPC_OUTCOME_UNAVAILABLE,
                        "GuardianUnavailable",
                    )
                }
            };
            Self::record_guardian_rpc_outcome(inner, rpc_outcome, rpc_elapsed);
            inner
                .metrics
                .leader_retries_total
                .with_label_values(&["withdrawal_signing", retry_label])
                .inc();
            anyhow::anyhow!("Guardian rejected withdrawal: {}", status.message())
        })?;

        let signed_response: GuardianSignedResponse<StandardWithdrawalResponse> = response_pb
            .try_into()
            .inspect_err(|_| {
                Self::record_guardian_rpc_outcome(
                    inner,
                    crate::metrics::GUARDIAN_RPC_OUTCOME_PARSE_ERROR,
                    rpc_elapsed,
                );
            })
            .map_err(|e| anyhow::anyhow!("Failed to parse guardian withdrawal response: {e}"))?;
        // Authenticated by TLS; the per-input BTC witness signatures below only
        // spend the 2-of-2 if they verify against the on-chain guardian BTC key
        // (enforced by Bitcoin), so the response itself isn't signature-checked.
        let response = signed_response.into_data_unchecked().response;

        anyhow::ensure!(
            response.enclave_signatures.len() == txn.inputs.len(),
            "Guardian returned {} enclave_signatures but tx has {} inputs",
            response.enclave_signatures.len(),
            txn.inputs.len(),
        );
        let guardian_signatures: Vec<Vec<u8>> = response
            .enclave_signatures
            .iter()
            .enumerate()
            .map(|(i, sig)| {
                let bytes = sig.to_vec();
                anyhow::ensure!(
                    bytes.len() == 64,
                    "Guardian enclave_signatures[{i}] is {} bytes, expected 64",
                    bytes.len(),
                );
                Ok(bytes)
            })
            .collect::<anyhow::Result<_>>()?;

        Self::record_guardian_rpc_outcome(
            inner,
            crate::metrics::GUARDIAN_RPC_OUTCOME_OK,
            rpc_elapsed,
        );
        info!(seq, "Guardian approved withdrawal");
        Ok(guardian_signatures)
    }

    fn record_guardian_rpc_outcome(inner: &Arc<Hashi>, outcome: &str, elapsed_secs: f64) {
        inner.metrics.record_guardian_rpc(
            crate::metrics::GUARDIAN_RPC_METHOD_STANDARD_WITHDRAWAL,
            outcome,
            elapsed_secs,
        );
    }

    async fn collect_guardian_withdrawal_signatures(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        members: &[CommitteeMember],
        timestamp_secs: u64,
        seq: u64,
    ) -> anyhow::Result<SignedMessage<StandardWithdrawalRequest>> {
        let guardian_request =
            crate::withdrawals::build_guardian_withdrawal_request(inner, txn, timestamp_secs, seq)?;

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let required_weight = certificate_threshold(committee.total_weight());

        let proto_request = SignGuardianWithdrawalRequestRequest {
            withdrawal_txn_id: txn.id.as_bytes().to_vec().into(),
            timestamp_secs,
            seq,
        };

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_guardian_withdrawal_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = committee
            .signature_aggregator(inner.config.hashi_ids().hashi_object_id, guardian_request);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(
                    withdrawal_txn_id = %txn.id,
                    "Failed to add guardian withdrawal signature: {e}"
                );
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient guardian withdrawal signatures: weight {weight} < {required_weight}"
            );
        }

        Ok(aggregator.finish()?)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_guardian_withdrawal_signature(
        inner: &Arc<Hashi>,
        proto_request: SignGuardianWithdrawalRequestRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting guardian withdrawal signature");

        let response = Self::call_peer_with_retry(
            inner,
            validator_address,
            "guardian withdrawal signature",
            move |mut client| {
                let request = proto_request.clone();
                async move { client.sign_guardian_withdrawal_request(request).await }
            },
        )
        .await?;

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse guardian withdrawal member signature from {validator_address}: {e}"
                );
            })
            .ok()
    }

    // ========================================================================
    // Guardian: committee handoff (post-rotation)
    // ========================================================================

    /// Replay stored guardian handoffs until the guardian matches the chain.
    async fn reconcile_guardian_committee(inner: &Arc<Hashi>) -> anyhow::Result<()> {
        let Some(guardian) = inner.guardian_client() else {
            return Ok(());
        };

        // Seed `guardian_epoch` once from `GetGuardianInfo`, then build the
        // full stored handoff chain and submit it to the guardian in one RPC.
        let info = inner.fetch_guardian_info_data().await?;
        let Some(mut guardian_epoch) = info.current_committee_epoch else {
            // ProvisionerInit hasn't run yet; the bootstrap CLI seeds it.
            return Ok(());
        };
        inner
            .metrics
            .guardian_current_committee_epoch
            .set(guardian_epoch as i64);

        let hashi_epoch = inner.onchain_state().epoch();
        let initial_guardian_epoch = guardian_epoch;
        let mut transitions = Vec::new();
        let mut final_to_epoch = guardian_epoch;
        loop {
            if guardian_epoch > hashi_epoch {
                // The guardian only advances via certs that hashi signs, so
                // it should never run ahead of the hashi chain. If we see
                // this, something is wrong (e.g., a stale onchain read).
                warn!(
                    guardian_epoch,
                    hashi_epoch, "guardian is ahead of hashi — unexpected"
                );
                return Ok(());
            }
            if guardian_epoch == hashi_epoch {
                break;
            }

            let from_epoch = guardian_epoch;
            info!(
                from_epoch,
                hashi_epoch, "Queueing stored guardian committee handoff"
            );
            let signed = inner
                .onchain_state()
                .committee_handoff(from_epoch)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing on-chain committee handoff for epoch {from_epoch}; cannot advance guardian"
                    )
                })?;
            let to_epoch = signed.message().new_committee.epoch;
            if to_epoch <= from_epoch {
                anyhow::bail!("stored guardian handoff did not advance: {from_epoch}->{to_epoch}");
            }
            transitions.push(signed_committee_transition_to_pb(&signed));
            final_to_epoch = to_epoch;
            guardian_epoch = to_epoch;
        }

        if transitions.is_empty() {
            return Ok(());
        }

        let resp = guardian
            .update_committee_chain(UpdateCommitteeChainRequest { transitions })
            .await
            .map_err(|status| {
                anyhow::anyhow!("UpdateCommitteeChain failed: {}", status.message())
            })?;
        let new_guardian_epoch = resp.current_committee_epoch.ok_or_else(|| {
            anyhow::anyhow!("UpdateCommitteeChain response missing current_committee_epoch")
        })?;
        inner
            .metrics
            .guardian_current_committee_epoch
            .set(new_guardian_epoch as i64);
        info!(
            from_epoch = initial_guardian_epoch,
            to_epoch = new_guardian_epoch,
            "Advanced guardian committee"
        );

        if new_guardian_epoch < final_to_epoch {
            anyhow::bail!(
                "guardian failed to advance to {final_to_epoch}: ended at {new_guardian_epoch}"
            );
        }

        Ok(())
    }

    pub(crate) async fn collect_committee_transition_signatures(
        inner: &Arc<Hashi>,
        from_epoch: u64,
    ) -> anyhow::Result<SignedMessage<CommitteeTransitionRequest>> {
        let (from_committee, new_committee) = inner
            .onchain_state()
            .committee_transition(from_epoch)
            .ok_or_else(|| {
                anyhow::anyhow!("no on-chain committee transition from epoch {from_epoch}")
            })?;
        let to_epoch = new_committee.epoch;

        // The verbatim on-chain committee: Move's
        // `submit_committee_handoff` verifies the aggregated cert over a
        // `CommitteeTransitionRequest` it rebuilds from the stored
        // committee, and every member signed exactly these bytes.
        let transition = CommitteeTransitionRequest { new_committee };
        let required_weight = certificate_threshold(from_committee.total_weight());

        let proto_request = SignCommitteeTransitionRequest { from_epoch };
        let mut sig_tasks = JoinSet::new();
        for member in from_committee.members() {
            let inner = inner.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_committee_transition_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = from_committee
            .signature_aggregator(inner.config.hashi_ids().hashi_object_id, transition);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(
                    from_epoch,
                    "Failed to add committee transition signature: {e}"
                );
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }
        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "insufficient committee transition signatures for {from_epoch}->{to_epoch}: weight {weight} < {required_weight}"
            );
        }
        Ok(aggregator.finish()?)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(validator = %member.validator_address())
    )]
    async fn request_committee_transition_signature(
        inner: &Arc<Hashi>,
        proto_request: SignCommitteeTransitionRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        let response = Self::call_peer_with_retry(
            inner,
            validator_address,
            "committee transition signature",
            move |mut client| async move { client.sign_committee_transition(proto_request).await },
        )
        .await?;
        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse committee transition signature from {validator_address}: {e}"
                );
            })
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::proto;
    use hashi_types::proto::guardian_service_server::GuardianService;
    use hashi_types::proto::guardian_service_server::GuardianServiceServer;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use tonic::Request;
    use tonic::Response;
    use tonic::Status;

    /// What the stub answers to `GetGuardianInfo`.
    #[derive(Clone, Copy)]
    enum InfoReply {
        /// A guardian with no committee: standby, or not yet activated.
        NoCommittee,
        Committee(u64),
        Unavailable,
    }

    #[derive(Clone)]
    struct StubGuardian {
        reply: Arc<Mutex<InfoReply>>,
        info_calls: Arc<AtomicUsize>,
    }

    fn info_response(current_committee_epoch: Option<u64>) -> proto::GetGuardianInfoResponse {
        let signing_pub_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes();
        proto::GetGuardianInfoResponse {
            info: Some(proto::GuardianInfoData {
                signing_pub_key: Some(signing_pub_key.to_vec().into()),
                encryption_pubkey: Some(vec![0; 32].into()),
                current_committee_epoch,
                ..Default::default()
            }),
            timestamp_ms: Some(1),
        }
    }

    #[tonic::async_trait]
    impl GuardianService for StubGuardian {
        async fn get_guardian_info(
            &self,
            _: Request<proto::GetGuardianInfoRequest>,
        ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
            self.info_calls.fetch_add(1, Ordering::SeqCst);
            let reply = *self.reply.lock().unwrap();
            match reply {
                InfoReply::NoCommittee => Ok(Response::new(info_response(None))),
                InfoReply::Committee(epoch) => Ok(Response::new(info_response(Some(epoch)))),
                InfoReply::Unavailable => Err(Status::unavailable("guardian down")),
            }
        }
        async fn get_attested_guardian_info(
            &self,
            _: Request<proto::GetAttestedGuardianInfoRequest>,
        ) -> Result<Response<proto::GetAttestedGuardianInfoResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn setup_new_key(
            &self,
            _: Request<proto::SetupNewKeyRequest>,
        ) -> Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn confirm_ceremony(
            &self,
            _: Request<proto::SignedCeremonyConfirmationRequest>,
        ) -> Result<Response<proto::CeremonyConfirmationResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn rotate_kp_set(
            &self,
            _: Request<proto::BatchProvisionerRotateKpSetRequest>,
        ) -> Result<Response<proto::SignedRotateKpSetResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn operator_init(
            &self,
            _: Request<proto::OperatorInitRequest>,
        ) -> Result<Response<proto::OperatorInitResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn provisioner_init(
            &self,
            _: Request<proto::BatchProvisionerInitRequest>,
        ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn provisioner_rotate_cert(
            &self,
            _: Request<proto::SignedProvisionerRotateCertRequest>,
        ) -> Result<Response<proto::SignedProvisionerRotateCertResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn operator_activate(
            &self,
            _: Request<proto::OperatorActivateRequest>,
        ) -> Result<Response<proto::OperatorActivateResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn standard_withdrawal(
            &self,
            _: Request<proto::SignedStandardWithdrawalRequest>,
        ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn update_committee(
            &self,
            _: Request<proto::SignedCommitteeTransition>,
        ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
        async fn update_committee_chain(
            &self,
            _: Request<proto::UpdateCommitteeChainRequest>,
        ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }
    }

    struct Harness {
        leader: LeaderService,
        guardian: StubGuardian,
        _tmpdir: tempfile::TempDir,
    }

    impl Harness {
        async fn new(hashi_epoch: u64, reply: InfoReply) -> Self {
            let guardian = StubGuardian {
                reply: Arc::new(Mutex::new(reply)),
                info_calls: Arc::default(),
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let incoming = futures::stream::unfold(listener, |listener| async move {
                let result = listener.accept().await.map(|(stream, _)| stream);
                Some((result, listener))
            });
            tokio::spawn(
                tonic::transport::Server::builder()
                    .add_service(GuardianServiceServer::new(guardian.clone()))
                    .serve_with_incoming(incoming),
            );

            let tmpdir = tempfile::tempdir().unwrap();
            let mut config = crate::config::Config::new_for_testing();
            config.db = Some(tmpdir.path().into());
            let hashi = Hashi::new_with_registry(
                crate::ServerVersion::new("unknown", "unknown"),
                None,
                config,
                &prometheus::Registry::new(),
            )
            .unwrap();
            hashi
                .onchain_state
                .set(crate::onchain::OnchainState::new_for_test(hashi_epoch))
                .unwrap();
            let client = hashi
                .new_guardian_client(&format!("http://{addr}"))
                .unwrap();
            hashi.guardian_client.set(Some(client)).unwrap();

            Self {
                leader: LeaderService::new(hashi),
                guardian,
                _tmpdir: tmpdir,
            }
        }

        fn set_reply(&self, reply: InfoReply) {
            *self.guardian.reply.lock().unwrap() = reply;
        }

        fn info_calls(&self) -> usize {
            self.guardian.info_calls.load(Ordering::SeqCst)
        }

        /// Awaits the reconcile task and applies its result the way the
        /// `guardian_committee_reconcile_task` arm of `LeaderService::run` does.
        async fn finish_reconcile(&mut self) -> anyhow::Result<()> {
            let task = self
                .leader
                .guardian_committee_reconcile_task
                .as_mut()
                .expect("a reconcile task is running");
            let result = task.await;
            self.leader.guardian_committee_reconcile_task = None;
            if !matches!(&result, Ok(Ok(()))) {
                self.leader.last_guardian_reconcile_epoch = None;
            }
            result.expect("reconcile task panicked")
        }
    }

    // F9: a guardian that reports no committee during the leader's
    // reconcile is not asked again in that hashi epoch, even once it
    // comes back on an older committee.
    #[tokio::test]
    async fn no_committee_reply_holds_the_epoch_gate_while_guardian_is_behind() {
        let mut h = Harness::new(5, InfoReply::NoCommittee).await;

        h.leader.check_reconcile_guardian_committee();
        h.finish_reconcile().await.unwrap();
        assert_eq!(h.info_calls(), 1);
        assert_eq!(h.leader.last_guardian_reconcile_epoch, Some(5));

        // The guardian is activated on the committee of epoch 4.
        h.set_reply(InfoReply::Committee(4));
        for _ in 0..3 {
            h.leader.check_reconcile_guardian_committee();
            assert!(h.leader.guardian_committee_reconcile_task.is_none());
        }
        assert_eq!(h.info_calls(), 1);
        assert_eq!(h.leader.last_guardian_reconcile_epoch, Some(5));

        // Only a hashi epoch change reopens the gate.
        h.leader.inner.onchain_state().set_epoch_for_test(6);
        h.leader.check_reconcile_guardian_committee();
        assert!(h.leader.guardian_committee_reconcile_task.is_some());
        let err = h.finish_reconcile().await.unwrap_err();
        assert_eq!(h.info_calls(), 2);
        assert!(
            err.to_string()
                .contains("missing on-chain committee handoff for epoch 4"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn unavailable_guardian_clears_the_epoch_gate_and_is_retried() {
        let mut h = Harness::new(5, InfoReply::Unavailable).await;

        h.leader.check_reconcile_guardian_committee();
        h.finish_reconcile().await.unwrap_err();
        assert_eq!(h.info_calls(), 1);
        assert_eq!(h.leader.last_guardian_reconcile_epoch, None);

        h.set_reply(InfoReply::Committee(4));
        h.leader.check_reconcile_guardian_committee();
        assert!(h.leader.guardian_committee_reconcile_task.is_some());
        let err = h.finish_reconcile().await.unwrap_err();
        assert_eq!(h.info_calls(), 2);
        // The retry reaches the handoff replay for the guardian's epoch.
        assert!(
            err.to_string()
                .contains("missing on-chain committee handoff for epoch 4"),
            "{err:#}"
        );
    }
}
