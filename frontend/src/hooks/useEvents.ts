import { useEffect, useRef, useState } from "react";
import type { TraceEvent } from "../types";

/**
 * The approval-lifecycle events. Exported so a view that only cares about the
 * queue can react to those without re-rendering on every credential
 * verification the trace also carries.
 */
export const APPROVAL_EVENT_TYPES = [
  "APPROVAL_REQUESTED", "APPROVAL_VIEWED", "APPROVAL_APPROVED",
  "APPROVAL_REJECTED", "APPROVAL_EXPIRED", "APPROVAL_CANCELLED",
  "APPROVAL_CONSUMED", "APPROVAL_SIGNOFF_RECORDED",
  "APPROVAL_DUAL_CONTROL_SATISFIED", "POLICY_ESCALATED",
] as const;

// Subscribers to approval-lifecycle events, kept module-level so several views
// share ONE EventSource. Opening a second stream per view would double the
// server's fan-out for no benefit.
type ApprovalListener = (eventType: string) => void;
const approvalListeners = new Set<ApprovalListener>();

/**
 * React to approval-lifecycle events on the EXISTING SSE stream.
 *
 * WHY THIS RATHER THAN A NEW REAL-TIME SUBSYSTEM (Phase 5.5, spec §12): the
 * stream already exists, already carries these events, and already survives
 * reconnection. Adding a socket layer for an approval queue would be a large
 * change to the least security-critical part of the system.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: carry any authorization meaning. An event
 * says "something changed, ask the server again". It never tells the console
 * that an approval succeeded -- the console re-reads the queue and the server
 * answers. A UI that trusted an event's contents would be trusting a broadcast
 * to tell it what it is allowed to see.
 */
export function useApprovalEvents(onChange: () => void): void {
  const handler = useRef(onChange);
  handler.current = onChange;

  useEffect(() => {
    const listener: ApprovalListener = () => handler.current();
    approvalListeners.add(listener);
    return () => {
      approvalListeners.delete(listener);
    };
  }, []);
}

/**
 * Subscribes to the backend's Server-Sent Events stream.
 *
 * Every event rendered by the UI arrives here, from the real backend event bus.
 * Nothing in this file synthesises an event: if the backend is quiet, the trace
 * stays empty, which is the honest display.
 */
export function useEvents(limit = 300) {
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    // replay=40 so the panel is not empty when the console is opened after
    // the backend has already been busy.
    const source = new EventSource("/api/v1/events/stream?replay=40");
    sourceRef.current = source;

    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as TraceEvent;
        setEvents((current) => [event, ...current].slice(0, limit));
      } catch {
        /* keepalive comments are not JSON; ignore them */
      }
    };
    // Named events (the backend sets `event: <TYPE>`) do not fire onmessage.
    const named = (message: MessageEvent) => {
      try {
        const event = JSON.parse(message.data) as TraceEvent;
        setEvents((current) => [event, ...current].slice(0, limit));
      } catch {
        /* ignore */
      }
    };
    const types = [
      "AGENT_CREATED", "DID_ASSIGNED", "KEY_GENERATED", "DID_DOCUMENT_PUBLISHED",
      "AGENT_ACTIVATED", "AGENT_SUSPENDED", "AGENT_TERMINATED",
      "SIGNATURE_CREATED", "SIGNATURE_VERIFIED", "SIGNATURE_INVALID",
      "AGENT_TASK_STARTED", "AGENT_TASK_COMPLETED", "AGENT_TASK_FAILED", "LLM_CALL",
      "CREDENTIAL_ISSUED", "CREDENTIAL_STORED", "CREDENTIAL_PRESENTED",
      "CREDENTIAL_VERIFICATION_STARTED", "CREDENTIAL_VERIFIED",
      "CREDENTIAL_VERIFICATION_FAILED", "CREDENTIAL_EXPIRED", "CREDENTIAL_REVOKED",
      "CREDENTIAL_REVOKED_REJECTED", "CREDENTIAL_SUBJECT_MISMATCH",
      "CREDENTIAL_SIGNATURE_INVALID", "CREDENTIAL_ISSUER_UNKNOWN",
      "PRESENTATION_VERIFIED", "PRESENTATION_VERIFICATION_FAILED",
      "ANS_AGENT_REGISTERED", "ANS_AGENT_UPDATED", "ANS_REGISTRATION_REJECTED",
      "ANS_SIGNATURE_INVALID", "ANS_HEARTBEAT_RECEIVED", "ANS_AGENT_STALE",
      "ANS_AGENT_OFFLINE", "ANS_AGENT_REVOKED", "ANS_AGENT_RESOLVED",
      "ANS_DISCOVERY_STARTED", "ANS_DISCOVERY_MATCH", "ANS_DISCOVERY_REJECTED",
      "ANS_DISCOVERY_NO_MATCH", "ANS_AGENT_SELECTED",
      "COORDINATOR_CAPABILITY_RESOLVED", "COORDINATOR_DISCOVERY_COMPLETE",
      "COORDINATOR_DISCOVERY_FAILED",
      // Phase 4 / 4.5 -- authorization, enforcement and the control plane.
      "AUTHORIZATION_REQUESTED", "PIP_CONTEXT_COLLECTED", "PDP_EVALUATION",
      "OPA_DECISION", "POLICY_ALLOW", "POLICY_DENY",
      "POLICY_HUMAN_APPROVAL_REQUIRED", "AUTHORIZATION_UNAVAILABLE",
      "AEM_INTERCEPT", "AEM_ALLOWED", "AEM_BLOCKED", "AEM_BYPASS_ATTEMPT",
      "TOOL_EXECUTED",
      "CONTROL_PLANE_AUTHENTICATED", "CONTROL_PLANE_REJECTED",
      "CONTROL_PLANE_AUTHORIZED", "CONTROL_PLANE_DENIED",
      "CONTROL_PLANE_REPLAY_DETECTED",
      // Phase 5 / 5.5 -- the human-in-the-loop cycle. These were declared in
      // the backend from Phase 5 but never listed here, so the live trace
      // showed everything EXCEPT the human step it exists to demonstrate.
      "HUMAN_AUTHENTICATED", "HUMAN_AUTHENTICATION_FAILED",
      "HUMAN_PRINCIPAL_REGISTERED",
      "APPROVAL_REQUESTED", "APPROVAL_VIEWED", "APPROVAL_APPROVED",
      "APPROVAL_REJECTED", "APPROVAL_EXPIRED", "APPROVAL_CANCELLED",
      "APPROVAL_CONSUMED", "APPROVAL_REPLAY_REJECTED",
      "AUTHORIZATION_REEVALUATED",
      "APPROVAL_SIGNOFF_RECORDED", "APPROVAL_DUPLICATE_APPROVER_REJECTED",
      "APPROVAL_SELF_APPROVAL_REJECTED", "APPROVAL_DUAL_CONTROL_SATISFIED",
      "POLICY_ESCALATED", "APPROVAL_KEY_ROTATED", "APPROVAL_KEY_REVOKED",
    ];

    // Events the approval queue cares about, fanned out to `useApprovalEvents`
    // subscribers. Registered on the SAME stream: a second EventSource would
    // double the server's fan-out for no benefit.
    const approvalEvent = (message: MessageEvent) => {
      approvalListeners.forEach((listener) => listener(message.type));
    };
    APPROVAL_EVENT_TYPES.forEach((type) =>
      source.addEventListener(type, approvalEvent as EventListener));
    types.forEach((type) => source.addEventListener(type, named as EventListener));

    return () => {
      APPROVAL_EVENT_TYPES.forEach((type) =>
        source.removeEventListener(type, approvalEvent as EventListener));
      types.forEach((type) => source.removeEventListener(type, named as EventListener));
      source.close();
    };
  }, [limit]);

  return { events, connected, clear: () => setEvents([]) };
}
