use bridge_protocol::{
    Channel, Conversation, ConversationKind, CostClass, DeliveryLedger, Envelope, EventId,
    IngressReject, Message, ObservedEvent, PaidPush, PlatformEventId, ProviderConversationId,
    ProviderSenderId, RegisteredBinding, SignatureVerdict, Timestamp, TraceId,
};
use std::collections::HashSet;

// Test-only platform and Agent stand-ins. The signature marker represents the
// platform verifier's result; it is deliberately not a cryptographic verifier.
struct MockPlatform {
    addressed_bot: &'static str,
    selected_binding: RegisteredBinding,
}

struct MockWebhook {
    signature_marker: &'static str,
    claimed_tenant: &'static str,
    claimed_binding: &'static str,
    observed: ObservedEvent,
}

#[derive(Debug, PartialEq, Eq)]
enum MockReject {
    WrongBinding,
    Admission(IngressReject),
}

#[derive(Default)]
struct MockAgent {
    calls: Vec<Envelope>,
}

impl MockAgent {
    fn start_or_continue(&mut self, envelope: &Envelope) {
        self.calls.push(envelope.clone());
    }
}

struct MockIngress {
    ledger: DeliveryLedger,
    agent: MockAgent,
    dispatched: HashSet<EventId>,
}

impl MockIngress {
    fn new(ledger: DeliveryLedger) -> Self {
        Self {
            ledger,
            agent: MockAgent::default(),
            dispatched: HashSet::new(),
        }
    }

    fn receive(
        &mut self,
        platform: &MockPlatform,
        webhook: &MockWebhook,
    ) -> Result<EventId, MockReject> {
        // The untrusted claims are present in the request but have no path to
        // DeliveryLedger::accept or the Agent's envelope.
        let _ = (webhook.claimed_tenant, webhook.claimed_binding);
        let verdict = if webhook.signature_marker == "mock-verified" {
            SignatureVerdict::Verified
        } else {
            SignatureVerdict::Failed
        };
        if verdict == SignatureVerdict::Verified
            && self.ledger.binding_for_bot(platform.addressed_bot)
                != Some(&platform.selected_binding)
        {
            return Err(MockReject::WrongBinding);
        }
        let event = self
            .ledger
            .accept(&platform.selected_binding, &webhook.observed, verdict)
            .map_err(MockReject::Admission)?;
        if self.dispatched.insert(event) {
            let envelope = self
                .ledger
                .export_envelope(event)
                .expect("accepted event exists");
            self.agent.start_or_continue(envelope);
        }
        Ok(event)
    }
}

fn webhook(event_id: &str, text: &str) -> MockWebhook {
    MockWebhook {
        signature_marker: "mock-verified",
        claimed_tenant: "attacker-tenant",
        claimed_binding: "attacker-binding",
        observed: ObservedEvent {
            platform_event_id: PlatformEventId::new(event_id.to_owned()),
            channel: Channel::Line,
            occurred_at: Timestamp::unix_millis(1_792_555_800_000),
            received_at: Timestamp::unix_millis(1_792_555_801_000),
            conversation: Conversation {
                provider_conversation_id: ProviderConversationId::new("room-1".to_owned()),
                kind: ConversationKind::Direct,
                sender_provider_id: ProviderSenderId::new("user-1".to_owned()),
            },
            message: Message::Text(text.to_owned()),
            reply_deadline: Timestamp::unix_millis(1_792_555_860_000),
            trace_id: TraceId::new("trace-1".to_owned()),
        },
    }
}

#[test]
fn mock_platform_to_agent_dispatches_once_and_fails_closed() {
    let mut ledger = DeliveryLedger::new();
    let owner = ledger
        .register_binding("org-a", "bind-a", "line-bot-U1")
        .unwrap();
    let other = ledger
        .register_binding("org-b", "bind-b", "line-bot-U2")
        .unwrap();
    let platform = MockPlatform {
        addressed_bot: "line-bot-U1",
        selected_binding: owner.clone(),
    };
    let wrong_route = MockPlatform {
        addressed_bot: "line-bot-U1",
        selected_binding: other,
    };
    let mut ingress = MockIngress::new(ledger);

    let mut bad_signature = webhook("wh-1", "还有法棍吗？");
    bad_signature.signature_marker = "invalid";
    assert_eq!(
        ingress.receive(&platform, &bad_signature),
        Err(MockReject::Admission(IngressReject::Signature))
    );
    assert_eq!(ingress.ledger.admitted_count(), 0);
    assert!(ingress.agent.calls.is_empty());

    let valid = webhook("wh-1", "还有法棍吗？");
    assert_ne!(valid.claimed_tenant, owner.tenant_id().as_str());
    assert_ne!(valid.claimed_binding, owner.binding_id().as_str());
    assert_eq!(
        ingress.receive(&wrong_route, &valid),
        Err(MockReject::WrongBinding)
    );
    assert_eq!(ingress.ledger.admitted_count(), 0);
    assert!(ingress.agent.calls.is_empty());

    let event = ingress.receive(&platform, &valid).unwrap();
    assert_eq!(ingress.ledger.admitted_count(), 1);
    assert_eq!(ingress.agent.calls.len(), 1);
    let delivered = &ingress.agent.calls[0];
    assert_eq!(delivered.event_id(), event);
    assert_eq!(delivered.tenant_id(), owner.tenant_id());
    assert_eq!(delivered.binding_id(), owner.binding_id());
    assert_eq!(
        delivered.provider_event_key().platform_event_id(),
        &valid.observed.platform_event_id
    );
    assert_eq!(
        delivered.message(),
        &Message::Text("还有法棍吗？".to_owned())
    );
    assert_eq!(delivered.paid_push(), &PaidPush::Denied);
    assert_eq!(delivered.cost_class(), CostClass::None);

    // A retry may carry different content; the stable scoped event ID must
    // prevent a second Agent call and preserve the first admitted envelope.
    let replay = webhook("wh-1", "duplicate payload");
    assert_eq!(ingress.receive(&platform, &replay), Ok(event));
    assert_eq!(ingress.ledger.admitted_count(), 1);
    assert_eq!(ingress.agent.calls.len(), 1);
    assert_eq!(
        ingress.ledger.export_envelope(event).unwrap().message(),
        &Message::Text("还有法棍吗？".to_owned())
    );
}
