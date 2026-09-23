### Diagnostics

- `gc_health_check` - tests environment, region normalization, OAuth token, and a small Genesys Cloud API call.
- `gc_permissions_check` - checks read-only access to users, roles, queues, groups, divisions, skills, wrap-up codes, analytics, and audit trail endpoints.

### Org and configuration audit

- `gc_org_summary` - high-level inventory totals for users, queues, roles, groups, divisions, skills, and wrap-up codes.
- `gc_audit_users` - detects inactive users with access/routing assignments, queue members without routing skills, users with many roles, missing email/division, duplicate display names, and users with roles but no queues.
- `gc_audit_roles` - detects broad role assignment, admin-like role names, unused roles, and potentially risky permissions.
- `gc_audit_queues` - detects queues with no members, missing division, unusual alerting timeout, and media/service-level risks.
- `gc_audit_routing` - checks queue staffing and sampled routing skills to identify routing/staffing risk.

### Conversation audit

- `gc_conversation_search` - searches conversation details by interval, queue, user, media type, direction, disconnect type, wrap-up code, ANI/DNIS, or conversation ID.
- `gc_conversation_detail` - returns a conversation summary and parsed segment timeline.
- `gc_conversation_timeline` - returns a simplified readable conversation timeline.
- `gc_disconnect_reason_audit` - audits disconnect reason distribution, peer disconnects, multiple queue hops, and missing wrap-up codes.
- `gc_queue_conversation_audit` - audits conversations for one queue and optionally includes analytics aggregate results.

### Reports

- `gc_audit_report_summary` - runs the v1 audit pack: org summary, users, roles, queues, and optionally conversations.
- `gc_audit_export_markdown` - converts audit results into a Markdown report.
- `gc_audit_export_csv` - converts audit findings into CSV.

## Recommended first test prompts in Claude

```text
Use genesys-cloud-data-collector and run gc_health_check.
```

```text
Run gc_permissions_check with includeOptional=false.
```

```text
Run gc_org_summary with includeSamples=true.
```

```text
Run gc_audit_report_summary with maxPages=5 and limitFindings=25.
```

```text
Audit conversations from the last 1 day for mediaType voice and show disconnect reasons.
```

```text
Show me the timeline for conversation ID <conversationId>.
```

## Required permissions depend on enabled tools

Core inventory/audit:

- `users:user:view`
- `authorization:role:view`
- `authorization:division:view`
- `routing:queue:view`
- `routing:skill:view`
- `routing:wrapupCode:view`
- `groups:group:view`

Conversation audit:

- `analytics:conversationDetail:view`
- `analytics:conversationAggregate:view`

Audit trail optional:

- `audits:audit:view`

## New v1.4.0 tools

- `gc_search_queues` - queue search with wildcard-style name patterns.
- `gc_query_queue_volumes` - queue conversation volume metrics for up to 300 queue IDs.
- `gc_sample_conversations_by_queue` - sample conversation IDs for a queue and interval.
- `gc_voice_call_quality` - voice-call quality extraction for conversation IDs, focusing on MOS-like values where available.
- `gc_conversation_sentiment` - Speech and Text Analytics sentiment extraction for conversation IDs.
- `gc_conversation_topics` - detected Speech and Text Analytics topics for a conversation.
- `gc_search_voice_conversations` - voice conversation search by interval and optional phone number.
- `gc_conversation_transcript` - structured transcript retrieval where recording/transcript data is available.
- `gc_oauth_clients` - OAuth client listing with optional role/division enrichment.
- `gc_oauth_client_usage` - OAuth/API usage query for an OAuth client and interval.

## Extra permissions for v1.4.0 tools

Depending on which new tools are used, the OAuth client may also need:

- `oauth:client:view`
- `usage:client:view`
- `recording:recording:view`
- `speechAndTextAnalytics:data:view`
- `speechAndTextAnalytics:topic:view`
- `analytics:speechAndTextAnalyticsAggregates:view`

## Suggested v1.4.0 test prompts

```text
Run gc_search_queues with name="*Support*" and pageSize=20.
```

```text
Run gc_sample_conversations_by_queue for queueId <queueId> for the last 1 day.
```

```text
Run gc_voice_call_quality for these conversation IDs: <conversationId>.
```

```text
Run gc_conversation_sentiment for these conversation IDs: <conversationId>.
```

```text
Run gc_conversation_transcript for conversation ID <conversationId>.
```

```text
Run gc_oauth_clients with pageSize=50.
```

---

# Genesys Cloud Org Audit MCP Upgrade v1.5.0

This build adds Architect flow component audit tools focused on the components used in flow routing logic.

## New flow tools

- `gc_flow_inventory` - list Architect flows and metadata, with optional flow type/name filters.
- `gc_flow_versions` - return the version history for a flow by `flowId` or `flowName`.
- `gc_flow_component_audit` - audit a single flow for queues, routing skills, language-skill lines, ACD priority, preferred-agent/agent-score lines, and unresolved references.
- `gc_audit_flows` - audit multiple flows and optionally scan a local directory containing Archy/Architect YAML exports.

## Deep flow analysis using Archy YAML

The Genesys Cloud API can list and retrieve flow metadata, but the full action-level flow logic is best inspected from an exported Architect/Archy YAML file. For a deep review of Transfer to ACD components, export the flow YAML and run:

```text
gc_flow_component_audit flowName="Main Inbound" archyYamlPath="C:\\flows\\Main Inbound.yaml" includeQueueMemberCounts=true
```

Or scan multiple exported YAML files:

```text
gc_audit_flows archyYamlDirectory="C:\\flows" maxFlows=50 includeQueueMemberCounts=true
```

## Flow component checks

The flow audit checks for:

- Queues referenced in the flow
- Routing skills referenced in the flow
- Language-skill related lines
- ACD priority values and expressions
- Preferred agent / agent score related lines
- Queues with no members
- Unresolved queue or skill references
- High static priority values above the review threshold


## v1.6.0 additions — Data Collection Engine + Full Object Lifecycle Audit

v1.6.0 keeps all existing tools from v1.5.0 and adds additive data-collection/object-audit tools:

### Data collection tools
- `gc_object_catalog` — shows supported object types and endpoints used by the audit engine.
- `gc_object_inventory` — collects selected object types with common inventory fields.
- `gc_collect_all_objects` — broad org object inventory collection.
- `gc_object_detail` — returns one object by type plus ID/name.
- `gc_collect_flow_components` — collects flow component dependencies such as queues, skills, schedules, schedule groups, data tables, data actions, prompts, wrap-up codes, ACD priority, and transfer targets.
- `gc_collect_flow_component_matrix` — creates a component-to-flow matrix.
- `gc_export_flow_components_csv` — exports flow component inventory as CSV.
- `gc_export_object_inventory_csv` — exports object inventory as CSV.
- `gc_export_object_inventory_markdown` — exports object inventory as Markdown.

### Object audit tools
- `gc_object_relationships` — finds where supported objects are used, especially which flows use a queue/skill/schedule/data table/data action/prompt/wrap-up code.
- `gc_object_change_history` — best-effort Audit API query for one object or raw audit query.
- `gc_audit_recent_admin_activity` — best-effort recent admin/audit activity query.
- `gc_audit_all_objects` — combined object inventory, lifecycle audit, and optional flow component audit.
- `gc_audit_object_lifecycle` — stale object, missing description, and missing division review.
- `gc_audit_stale_objects` — stale object review by modified/created date.
- `gc_audit_orphaned_objects` — detects components not found in scanned flows; this is review-needed only, not a delete recommendation.
- `gc_audit_flow_components` — audits flow component findings from collected flow components.

### Example prompts

```text
Run gc_object_catalog.
```

```text
Collect all queues, flows, schedules, data tables, data actions, and OAuth clients with id, name, division, createdDate, modifiedDate, and description.
```

```text
Run gc_collect_flow_components with archyYamlDirectory="C:\\flows", maxFlows=50, and includeMatrix=true.
```

```text
Export all flow components to CSV with Flow Name, Queues, Skills, Schedules, Data Tables, Data Actions, Prompts, Wrap-up Codes, and Priority.
```

```text
Run gc_audit_all_objects with staleDays=365, includeFlowAudit=true, and maxFlows=50.
```

### Notes

- Flow component deep inspection works best when you provide exported Architect/Archy YAML using `archyYamlDirectory`, `archyYamlPath`, or `yamlText`.
- Audit API tools are best-effort and depend on `audits:audit:view`, Audit API topic availability, serviceName, and retention/real-time limits.
- Orphaned object checks only mean “not detected in scanned flow sources”; confirm manually before cleanup because objects can be used outside Architect flows.


---

# Channel Blueprint Reporting Layer v1.7.0

This additive release keeps all previous data collection and audit tools, and adds a Blueprint-specific reporting layer aligned to the Channel Blueprint Discovery Findings template.

## New Blueprint tools

- `gc_blueprint_assessment_map` - maps assessment sections to MCP tools, evidence types, coverage, and gaps.
- `gc_blueprint_evidence_pack` - gathers org summary, audit findings, object lifecycle evidence, flow components, optional conversation analytics, and optional discovery notes.
- `gc_blueprint_member_journey_observations` - drafts Section 2 observations for entry complexity, authentication friction, transfer behaviour, escalation points, and self-service opportunities.
- `gc_blueprint_agent_team_leader_observations` - drafts Section 3 observations for manual intervention, knowledge dependency, queue management, escalation behaviour, and hold drivers.
- `gc_blueprint_channel_routing_observations` - drafts Section 4 observations for intent vs organisation, queue purpose, routing decisions, specialist pathways, workarounds, and channel usage.
- `gc_blueprint_governance_observations` - drafts Section 5 observations for ownership, change management, dependency risks, standards, and consistency.
- `gc_blueprint_emerging_themes` - drafts Section 6 themes from platform evidence and supplied discovery notes.
- `gc_blueprint_opportunity_summary` - drafts Section 7 opportunity summary with evidence, benefit, priority, and further investigation items.
- `gc_blueprint_discovery_summary` - drafts Section 8 strengths, challenges, opportunities, design considerations, and narrative.
- `gc_blueprint_export_markdown` - exports a Channel Blueprint draft in Markdown.
- `gc_blueprint_export_docx_payload` - returns a JSON payload that can be used to populate the Word template.

## Notes

Blueprint outputs are evidence drafts. They should be validated against workshops, interviews, agent observations, journey walkthroughs, call listening sessions, process reviews, and documentation review before client use.


## v1.9.0 - Channel Blueprint Metrics and Statistics Layer

Adds metrics/statistics tools for the Channel Blueprint reporting layer:

- `gc_blueprint_metrics_pack` - consolidated platform metrics/statistics for an interval, including offered, answered, abandoned, transferred, answer/abandon/transfer rates, and average wait/talk/hold/ACW/handle times.
- `gc_blueprint_channel_statistics` - channel usage statistics by media type and direction, with optional trend rows.
- `gc_blueprint_queue_statistics` - queue-level statistics for the Blueprint evidence pack.
- `gc_blueprint_export_metrics_csv` - exports metrics/statistics rows to CSV for evidence appendices or workbook use.

The Blueprint evidence pack and Markdown/DOCX payload exports now include a metrics snapshot when `includeMetrics` is enabled.

Example prompts in Claude Desktop:

```text
Run gc_blueprint_metrics_pack with days=30, includeQueueMetrics=true, includeChannelMetrics=true, includeTrendMetrics=true.

Run gc_blueprint_queue_statistics with days=30 and mediaType=voice.

Run gc_blueprint_evidence_pack with includeMetrics=true, metricsArgs={"days":30,"includeTrendMetrics":true}.

Run gc_blueprint_export_metrics_csv with days=30, includeQueueMetrics=true, includeChannelMetrics=true.
```


## v1.9.0 Usage, Subscription, Billing and License Audit Tools

This version adds best-effort usage and subscription audit tools:

- `gc_license_users` — list user license assignments where the License Users API is available.
- `gc_license_usage_summary` — summarize assigned licenses by product/license.
- `gc_api_usage_summary` — review API usage by OAuth client where API usage query data is available.
- `gc_subscription_overview` — best-effort subscription/billing overview. Access varies by org and billing API availability.
- `gc_billable_usage_report` — best-effort billable usage report. Access and fields vary by org/account type.
- `gc_ai_usage_audit` — extract AI/token/Copilot/Agent Assist/transcription usage signals where billing data exposes them.
- `gc_subscription_usage_audit` — combined audit for licensing, API usage, billing/subscription usage, and AI usage signals.

Billing and subscription data can be restricted by Genesys account type, partner status, permissions, and API availability. Always validate final billing numbers in the Genesys Billing and Usage UI or official billing exports.
