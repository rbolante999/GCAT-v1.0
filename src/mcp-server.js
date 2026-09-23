#!/usr/bin/env node
import "dotenv/config";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  McpError,
  ErrorCode
} from "@modelcontextprotocol/sdk/types.js";

import {
  RESOURCE_CATALOG,
  cacheStats,
  cacheClear,
  snapshotStatus,
  snapshotClearTool,
  snapshotBuildTool,
  gcListTool,
  gcExportCsvTool,
  gcSearchTool,
  gcUserProfileTool,
  gcHealthCheckTool,
  gcPermissionsCheckTool,
  gcOrgSummaryTool,
  gcAuditUsersTool,
  gcAuditRolesTool,
  gcAuditQueuesTool,
  gcAuditRoutingTool,
  gcConversationSearchTool,
  gcConversationDetailTool,
  gcConversationTimelineTool,
  gcDisconnectReasonAuditTool,
  gcQueueConversationAuditTool,
  gcAuditReportSummaryTool,
  gcAuditExportMarkdownTool,
  gcAuditExportCsvTool,
  gcSearchQueuesTool,
  gcQueryQueueVolumesTool,
  gcSampleConversationsByQueueTool,
  gcVoiceCallQualityTool,
  gcConversationSentimentTool,
  gcConversationTopicsTool,
  gcSearchVoiceConversationsTool,
  gcConversationTranscriptTool,
  gcOauthClientsTool,
  gcOauthClientUsageTool,
  gcLicenseUsersTool,
  gcLicenseUsageSummaryTool,
  gcApiUsageSummaryTool,
  gcSubscriptionOverviewTool,
  gcBillableUsageReportTool,
  gcAiUsageAuditTool,
  gcSubscriptionUsageAuditTool,
  gcFlowInventoryTool,
  gcFlowVersionsTool,
  gcFlowComponentAuditTool,
  gcAuditFlowsTool,

  gcObjectCatalogTool,
  gcObjectInventoryTool,
  gcCollectAllObjectsTool,
  gcObjectDetailTool,
  gcObjectRelationshipsTool,
  gcObjectChangeHistoryTool,
  gcAuditRecentAdminActivityTool,
  gcAuditAllObjectsTool,
  gcAuditObjectLifecycleTool,
  gcAuditStaleObjectsTool,
  gcAuditOrphanedObjectsTool,
  gcCollectFlowComponentsTool,
  gcCollectFlowComponentMatrixTool,
  gcExportFlowComponentsCsvTool,
  gcAuditFlowComponentsTool,
  gcExportObjectInventoryCsvTool,
  gcExportObjectInventoryMarkdownTool,

  gcBlueprintAssessmentMapTool,
  gcBlueprintEvidencePackTool,
  gcBlueprintMetricsPackTool,
  gcBlueprintChannelStatisticsTool,
  gcBlueprintQueueStatisticsTool,
  gcBlueprintExportMetricsCsvTool,
  gcBlueprintMemberJourneyObservationsTool,
  gcBlueprintAgentTeamLeaderObservationsTool,
  gcBlueprintChannelRoutingObservationsTool,
  gcBlueprintGovernanceObservationsTool,
  gcBlueprintEmergingThemesTool,
  gcBlueprintOpportunitySummaryTool,
  gcBlueprintDiscoverySummaryTool,
  gcBlueprintExportMarkdownTool,
  gcBlueprintExportDocxPayloadTool,

  // NEW TOP 5
  gcUserAccessSummaryTool,
  gcQueueStaffingTool,
  gcRoleImpactTool,
  gcQueueOverviewTool,
  gcUserRoutingProfileTool
} from "./gc-core.js";

function asMcpError(err) {
  const msg = String(err?.message || err || "Unknown error");
  return new McpError(ErrorCode.InternalError, msg);
}

const server = new Server(
  { name: "gc-org-audit", version: "1.9.0" },
  { capabilities: { tools: {} } }
);

const tools = [
  {
    name: "gc_catalog",
    description: "Return available resources and fields (users, roles, queues, groups).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "gc_cache_stats",
    description: "Get in-memory cache stats (alive/expired/inflight).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "gc_cache_clear",
    description: "Clear in-memory cache and token cache.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "gc_snapshot_status",
    description: "Get snapshot status (enabled, READY/BUILDING/FAILED, expiry).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "gc_snapshot_clear",
    description: "Clear snapshot data.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "gc_health_check",
    description: "Diagnose Genesys Cloud connection: env variables, region normalization, OAuth token, and a small API call. Does not reveal secrets.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "gc_permissions_check",
    description: "Test read-only API permissions for users, roles, queues, groups, divisions, skills, wrap-up codes, analytics, and audit trail.",
    inputSchema: {
      type: "object",
      properties: {
        includeOptional: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_org_summary",
    description: "Return high-level Genesys Cloud org inventory totals for users, queues, roles, groups, divisions, skills, and wrap-up codes.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeSamples: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_users",
    description: "Audit Genesys Cloud users for inactive access, queue/skill mismatches, missing email/division, duplicate names, and excessive roles.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeInactiveUsers: { type: "boolean" },
        enrich: { type: "boolean" },
        excessiveRoleThreshold: { type: "integer", minimum: 1, maximum: 50 },
        limitFindings: { type: "integer", minimum: 1, maximum: 1000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_roles",
    description: "Audit Genesys Cloud roles for risky/elevated permissions, broad assignment, admin-like roles, and unused roles.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        enrich: { type: "boolean" },
        memberCountThreshold: { type: "integer", minimum: 1, maximum: 10000 },
        limitFindings: { type: "integer", minimum: 1, maximum: 1000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_queues",
    description: "Audit queue configuration for no members, division gaps, media settings, alerting timeout, and service-level risks.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeMemberCounts: { type: "boolean" },
        limitFindings: { type: "integer", minimum: 1, maximum: 1000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_routing",
    description: "Audit routing/staffing for queues: member availability and sampled member routing skills.",
    inputSchema: {
      type: "object",
      properties: {
        maxQueues: { type: "integer", minimum: 1, maximum: 200 },
        includeMemberSkills: { type: "boolean" },
        memberSampleSize: { type: "integer", minimum: 1, maximum: 200 },
        limitFindings: { type: "integer", minimum: 1, maximum: 1000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_snapshot_build",
    description: "Build snapshot in memory (heavy operation but reduces subsequent API use).",
    inputSchema: {
      type: "object",
      properties: {
        resources: { type: "array", items: { type: "string" } },
        includeInactiveUsers: { type: "boolean" },
        enrichUsers: { type: "boolean" },
        enrichRoles: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_list",
    description: "List a resource (users/roles/queues/groups) with pagination.",
    inputSchema: {
      type: "object",
      properties: {
        resource: { type: "string", enum: Object.keys(RESOURCE_CATALOG) },
        pageNumber: { type: "integer", minimum: 1 },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        fields: { type: "array", items: { type: "string" } },
        enrichPreview: { type: "boolean" },
        useSnapshot: { type: "boolean" },
        includeInactiveUsers: { type: "boolean" }
      },
      required: ["resource"],
      additionalProperties: false
    }
  },
  {
    name: "gc_export_csv",
    description: "Export resource to CSV (mode=page|all).",
    inputSchema: {
      type: "object",
      properties: {
        resource: { type: "string", enum: Object.keys(RESOURCE_CATALOG) },
        fields: { type: "array", items: { type: "string" } },
        mode: { type: "string", enum: ["page", "all"] },
        includeInactiveUsers: { type: "boolean" },
        pageNumber: { type: "integer", minimum: 1 },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        useSnapshot: { type: "boolean" }
      },
      required: ["resource"],
      additionalProperties: false
    }
  },
  {
    name: "gc_search",
    description: "Cross-search users/queues/groups/roles using Genesys Cloud APIs directly (NO snapshot).",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", minLength: 1 },
        resources: { type: "array", items: { type: "string" } },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        limit: { type: "integer", minimum: 1, maximum: 200 }
      },
      required: ["query"],
      additionalProperties: false
    }
  },

  {
    name: "gc_conversation_search",
    description: "Search conversation details by interval, queue, user, media type, direction, disconnect type, wrap-up code, ANI/DNIS, or conversationId.",
    inputSchema: {
      type: "object",
      properties: {
        conversationId: { type: "string" },
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 90 },
        pageNumber: { type: "integer", minimum: 1 },
        pageSize: { type: "integer", minimum: 1, maximum: 100 },
        queueId: { type: "string" },
        userId: { type: "string" },
        mediaType: { type: "string" },
        direction: { type: "string" },
        disconnectType: { type: "string" },
        wrapUpCode: { type: "string" },
        ani: { type: "string" },
        dnis: { type: "string" },
        rawQuery: { type: "object" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_conversation_detail",
    description: "Get a single conversation detail and parsed segment timeline by conversationId.",
    inputSchema: {
      type: "object",
      properties: {
        conversationId: { type: "string" },
        includeRaw: { type: "boolean" }
      },
      required: ["conversationId"],
      additionalProperties: false
    }
  },
  {
    name: "gc_conversation_timeline",
    description: "Return a simplified readable timeline for a conversationId.",
    inputSchema: {
      type: "object",
      properties: { conversationId: { type: "string" } },
      required: ["conversationId"],
      additionalProperties: false
    }
  },
  {
    name: "gc_disconnect_reason_audit",
    description: "Audit conversations for disconnect reason distribution, peer disconnects, missing wrap-up codes, and multiple queue hops.",
    inputSchema: {
      type: "object",
      properties: {
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 90 },
        pageSize: { type: "integer", minimum: 1, maximum: 100 },
        maxPages: { type: "integer", minimum: 1, maximum: 20 },
        queueId: { type: "string" },
        userId: { type: "string" },
        mediaType: { type: "string" },
        direction: { type: "string" },
        disconnectType: { type: "string" },
        wrapUpCode: { type: "string" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_queue_conversation_audit",
    description: "Audit conversations for one queue by date interval and return details-based metrics plus optional analytics aggregate results.",
    inputSchema: {
      type: "object",
      properties: {
        queueId: { type: "string" },
        queueName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 90 },
        pageSize: { type: "integer", minimum: 1, maximum: 100 },
        maxPages: { type: "integer", minimum: 1, maximum: 20 },
        mediaType: { type: "string" },
        direction: { type: "string" },
        includeAggregateQuery: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_report_summary",
    description: "Run the first upgrade audit pack: org summary, user audit, role audit, queue audit, and optional conversation audit.",
    inputSchema: {
      type: "object",
      properties: {
        includeConversations: { type: "boolean" },
        conversationArgs: { type: "object" },
        maxPages: { type: "integer", minimum: 1, maximum: 100 },
        limitFindings: { type: "integer", minimum: 1, maximum: 500 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_export_markdown",
    description: "Create a Markdown audit report from a supplied auditResult, or run a summary audit if no result is supplied.",
    inputSchema: {
      type: "object",
      properties: {
        auditResult: { type: "object" },
        includeDetails: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_export_csv",
    description: "Create CSV rows from audit findings in a supplied auditResult, or run a summary audit if no result is supplied.",
    inputSchema: {
      type: "object",
      properties: { auditResult: { type: "object" } },
      additionalProperties: false
    }
  },


  // MakingChatbots-inspired insights / parity tools
  {
    name: "gc_search_queues",
    description: "Search Genesys Cloud queues by name, including wildcard-style patterns such as '*Support*'. Inspired by the MakingChatbots search_queues tool.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        pageNumber: { type: "integer", minimum: 1 },
        pageSize: { type: "integer", minimum: 1, maximum: 500 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_query_queue_volumes",
    description: "Return conversation volume metrics for up to 300 queue IDs between two dates using analytics aggregates.",
    inputSchema: {
      type: "object",
      properties: {
        queueIds: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 300 },
        startDate: { type: "string" },
        endDate: { type: "string" },
        interval: { type: "string" },
        mediaType: { type: "string" }
      },
      required: ["queueIds"],
      additionalProperties: false
    }
  },
  {
    name: "gc_sample_conversations_by_queue",
    description: "Retrieve a sample of conversation IDs and summaries for a queue between two dates.",
    inputSchema: {
      type: "object",
      properties: {
        queueId: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        interval: { type: "string" },
        sampleSize: { type: "integer", minimum: 1, maximum: 100 },
        pageSize: { type: "integer", minimum: 1, maximum: 100 },
        mediaType: { type: "string" },
        direction: { type: "string" }
      },
      required: ["queueId"],
      additionalProperties: false
    }
  },
  {
    name: "gc_voice_call_quality",
    description: "Retrieve voice call quality indicators for one or more conversation IDs, focusing on MOS-like values when available in analytics details.",
    inputSchema: {
      type: "object",
      properties: {
        conversationIds: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 100 },
        includeRaw: { type: "boolean" }
      },
      required: ["conversationIds"],
      additionalProperties: false
    }
  },
  {
    name: "gc_conversation_sentiment",
    description: "Retrieve Speech and Text Analytics sentiment for one or more conversations, where transcript/STA data is available.",
    inputSchema: {
      type: "object",
      properties: {
        conversationIds: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 100 },
        includeRaw: { type: "boolean" }
      },
      required: ["conversationIds"],
      additionalProperties: false
    }
  },
  {
    name: "gc_conversation_topics",
    description: "Retrieve detected Speech and Text Analytics topics for a conversation, where topics are available.",
    inputSchema: {
      type: "object",
      properties: {
        conversationId: { type: "string" },
        includeRaw: { type: "boolean" }
      },
      required: ["conversationId"],
      additionalProperties: false
    }
  },
  {
    name: "gc_search_voice_conversations",
    description: "Search voice conversations by date range and optional ANI/DNIS phone number. Returns conversation IDs and metadata for further analysis.",
    inputSchema: {
      type: "object",
      properties: {
        phoneNumber: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        interval: { type: "string" },
        pageNumber: { type: "integer", minimum: 1 },
        pageSize: { type: "integer", minimum: 1, maximum: 100 },
        direction: { type: "string" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_conversation_transcript",
    description: "Retrieve a structured transcript for a conversation if recording and Speech/Text Analytics transcript data is available.",
    inputSchema: {
      type: "object",
      properties: {
        conversationId: { type: "string" },
        includeRaw: { type: "boolean" },
        maxCommunicationsToTry: { type: "integer", minimum: 1, maximum: 100 }
      },
      required: ["conversationId"],
      additionalProperties: false
    }
  },
  {
    name: "gc_oauth_clients",
    description: "List OAuth clients with grant type, state, and optional role/division name enrichment for API/integration audit.",
    inputSchema: {
      type: "object",
      properties: {
        pageNumber: { type: "integer", minimum: 1 },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        includeRoleNames: { type: "boolean" },
        includeDivisionNames: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_oauth_client_usage",
    description: "Retrieve OAuth client API usage for a date range where API usage data is available.",
    inputSchema: {
      type: "object",
      properties: {
        oauthClientId: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        interval: { type: "string" }
      },
      required: ["oauthClientId"],
      additionalProperties: false
    }
  },

  {
    name: "gc_license_users",
    description: "List Genesys Cloud user license assignments using the License Users API where available.",
    inputSchema: {
      type: "object",
      properties: {
        pageNumber: { type: "integer", minimum: 1 },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        includeRaw: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_license_usage_summary",
    description: "Summarize license assignment counts by license/product and optionally list user-level license assignments.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeUserBreakdown: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_api_usage_summary",
    description: "Audit API usage by OAuth client for a date range using Genesys API usage query data where available.",
    inputSchema: {
      type: "object",
      properties: {
        oauthClientIds: { type: "array", items: { type: "string" } },
        startDate: { type: "string" },
        endDate: { type: "string" },
        interval: { type: "string" },
        maxClients: { type: "integer", minimum: 1, maximum: 200 },
        topN: { type: "integer", minimum: 1, maximum: 500 },
        includeRaw: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_subscription_overview",
    description: "Best-effort subscription/billing overview query for the current organization. Availability depends on Genesys billing API access.",
    inputSchema: {
      type: "object",
      properties: {
        periodEndingTimestamp: { type: "string" },
        includeRaw: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_billable_usage_report",
    description: "Best-effort billable usage report query for billing/usage audit. Endpoint availability and fields vary by org/account type.",
    inputSchema: {
      type: "object",
      properties: {
        startDate: { type: "string" },
        endDate: { type: "string" },
        includeRaw: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_ai_usage_audit",
    description: "Extract AI Experience, token, Copilot, Agent Assist, transcription, sentiment, and topic usage signals from available billing/subscription data.",
    inputSchema: {
      type: "object",
      properties: {
        periodEndingTimestamp: { type: "string" },
        includeRaw: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_subscription_usage_audit",
    description: "Combined usage audit: license assignments, API usage, billing/subscription overview, billable usage, and AI/token signals where available.",
    inputSchema: {
      type: "object",
      properties: {
        days: { type: "integer", minimum: 1, maximum: 366 },
        includeLicenseUsage: { type: "boolean" },
        includeApiUsage: { type: "boolean" },
        includeBillingUsage: { type: "boolean" },
        includeAiUsage: { type: "boolean" },
        maxClients: { type: "integer", minimum: 1, maximum: 200 },
        includeRaw: { type: "boolean" }
      },
      additionalProperties: false
    }
  },


  // Architect flow component audit tools (v1.5.0)
  {
    name: "gc_flow_inventory",
    description: "List Architect flows and basic metadata. Optional filters by flow type/name and optional detail enrichment.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        flowType: { type: "string" },
        flowName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        includeDetails: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_flow_versions",
    description: "Return version history for an Architect flow by flowId or flowName.",
    inputSchema: {
      type: "object",
      properties: {
        flowId: { type: "string" },
        flowName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_flow_component_audit",
    description: "Audit one Architect flow for queues, routing skills, language-skill lines, ACD priority, preferred-agent/agent-score lines, and unresolved references. For deep logic, provide Archy YAML using archyYamlPath or yamlText.",
    inputSchema: {
      type: "object",
      properties: {
        flowId: { type: "string" },
        flowName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        yamlText: { type: "string" },
        archyYamlPath: { type: "string" },
        includeQueueMemberCounts: { type: "boolean" },
        priorityReviewThreshold: { type: "integer", minimum: 1, maximum: 25000000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_flows",
    description: "Audit multiple Architect flows for routing components used in flows: queues, skills, ACD priority, preferred-agent/agent-score references, unresolved queues/skills, and queue staffing risks. Optionally scans Archy YAML files from a local directory.",
    inputSchema: {
      type: "object",
      properties: {
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxFlows: { type: "integer", minimum: 1, maximum: 200 },
        flowType: { type: "string" },
        flowName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        archyYamlDirectory: { type: "string" },
        includeQueueMemberCounts: { type: "boolean" },
        priorityReviewThreshold: { type: "integer", minimum: 1, maximum: 25000000 },
        limitFindings: { type: "integer", minimum: 1, maximum: 1000 }
      },
      additionalProperties: false
    }
  },

  // Existing (kept)
  {
    name: "gc_user_profile",
    description: "Get full user profile by userId including roles, queues, skills, and groups.",
    inputSchema: {
      type: "object",
      properties: { userId: { type: "string" } },
      required: ["userId"],
      additionalProperties: false
    }
  },

  // ✅ NEW TOP 5
  {
    name: "gc_user_access_summary",
    description: "Find user(s) and return their access summary (roles/queues/skills). Uses live APIs (NO snapshot).",
    inputSchema: {
      type: "object",
      properties: {
        userId: { type: "string" },
        userQuery: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        limit: { type: "integer", minimum: 1, maximum: 50 },
        includeGroups: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_queue_staffing",
    description: "Get queue members (name/username/email) and optionally their routing skills. Uses live APIs (NO snapshot).",
    inputSchema: {
      type: "object",
      properties: {
        queueId: { type: "string" },
        queueName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        limitMembers: { type: "integer", minimum: 1, maximum: 2000 },
        includeMemberSkills: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_role_impact",
    description: "Summarize a role: permissions + member list (names/usernames). Uses live APIs (NO snapshot).",
    inputSchema: {
      type: "object",
      properties: {
        roleId: { type: "string" },
        roleName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        includeMembers: { type: "boolean" },
        membersLimit: { type: "integer", minimum: 1, maximum: 2000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_queue_overview",
    description: "Get queue configuration overview (division/media settings/member count). Uses live APIs (NO snapshot).",
    inputSchema: {
      type: "object",
      properties: {
        queueId: { type: "string" },
        queueName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        includeMembersCount: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_user_routing_profile",
    description: "Return a user’s routing profile view: queues + routing skills (with proficiency) + roles. Uses live APIs (NO snapshot).",
    inputSchema: {
      type: "object",
      properties: {
        userId: { type: "string" },
        userQuery: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] }
      },
      additionalProperties: false
    }
  },
  // v1.6.0 - Data collection and full object lifecycle audit tools
  {
    name: "gc_object_catalog",
    description: "List supported Genesys Cloud object types for inventory, collection, lifecycle audit, and change-history audit.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "gc_object_inventory",
    description: "Collect current-state inventory for selected Genesys Cloud object types with ID, name, division, created date, modified date, state, and selected fields.",
    inputSchema: {
      type: "object",
      properties: {
        objectTypes: { type: "array", items: { type: "string" } },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeDetails: { type: "boolean" },
        fields: { type: "array", items: { type: "string" } },
        includeErrors: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_collect_all_objects",
    description: "Collect broad current-state object inventory across the org. Useful as the Data Collection Engine base dataset.",
    inputSchema: {
      type: "object",
      properties: {
        objectTypes: { type: "array", items: { type: "string" } },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeDetails: { type: "boolean" },
        fields: { type: "array", items: { type: "string" } },
        includeErrors: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_object_detail",
    description: "Get one object detail by object type plus ID or name. Supports users, queues, roles, flows, data actions, schedules, OAuth clients, and other supported object types.",
    inputSchema: {
      type: "object",
      properties: {
        objectType: { type: "string" },
        objectId: { type: "string" },
        objectName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        includeRaw: { type: "boolean" }
      },
      required: ["objectType"],
      additionalProperties: false
    }
  },
  {
    name: "gc_object_relationships",
    description: "Find known relationships/dependencies for an object, especially which Architect flows use a queue, skill, schedule, data table, data action, prompt, or wrap-up code.",
    inputSchema: {
      type: "object",
      properties: {
        objectType: { type: "string" },
        objectId: { type: "string" },
        objectName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        archyYamlDirectory: { type: "string" },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 }
      },
      required: ["objectType"],
      additionalProperties: false
    }
  },
  {
    name: "gc_object_change_history",
    description: "Query Genesys Cloud Audit API for change history for an object or raw audit query. Useful for who changed what, when, and object lifecycle review.",
    inputSchema: {
      type: "object",
      properties: {
        objectType: { type: "string" },
        objectId: { type: "string" },
        objectName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        serviceName: { type: "string" },
        entityType: { type: "string" },
        useRealtime: { type: "boolean" },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        pageNumber: { type: "integer", minimum: 1 },
        rawQuery: { type: "object" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_recent_admin_activity",
    description: "Query recent audit/admin activity across the org through the Genesys Cloud Audit API.",
    inputSchema: {
      type: "object",
      properties: {
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        serviceName: { type: "string" },
        useRealtime: { type: "boolean" },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        pageNumber: { type: "integer", minimum: 1 },
        rawQuery: { type: "object" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_all_objects",
    description: "Run full object audit combining object inventory, lifecycle findings, and optional flow component audit.",
    inputSchema: {
      type: "object",
      properties: {
        objectTypes: { type: "array", items: { type: "string" } },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        staleDays: { type: "integer", minimum: 1, maximum: 3650 },
        includeFlowAudit: { type: "boolean" },
        archyYamlDirectory: { type: "string" },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        limitFindings: { type: "integer", minimum: 1, maximum: 5000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_object_lifecycle",
    description: "Audit object lifecycle risks: stale objects, missing descriptions, missing/unavailable divisions, and maintenance concerns.",
    inputSchema: {
      type: "object",
      properties: {
        objectTypes: { type: "array", items: { type: "string" } },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        staleDays: { type: "integer", minimum: 1, maximum: 3650 },
        missingDescription: { type: "boolean" },
        missingDivision: { type: "boolean" },
        limitFindings: { type: "integer", minimum: 1, maximum: 5000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_stale_objects",
    description: "Find objects that have not been modified for the selected staleDays threshold.",
    inputSchema: {
      type: "object",
      properties: {
        objectTypes: { type: "array", items: { type: "string" } },
        staleDays: { type: "integer", minimum: 1, maximum: 3650 },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        limitFindings: { type: "integer", minimum: 1, maximum: 5000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_orphaned_objects",
    description: "Detect objects not found in scanned Architect flows, such as queues, skills, data tables, data actions, schedules, prompts, and wrap-up codes. Treat as review-needed, not automatic deletion.",
    inputSchema: {
      type: "object",
      properties: {
        archyYamlDirectory: { type: "string" },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        limitFindings: { type: "integer", minimum: 1, maximum: 5000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_collect_flow_components",
    description: "Collect flow component inventory: Flow Name, queues, skills, language skills, schedules, schedule groups, data tables, data actions, prompts, wrap-up codes, ACD priorities, and transfer targets. Supports deeper Archy YAML scanning.",
    inputSchema: {
      type: "object",
      properties: {
        flowId: { type: "string" },
        flowName: { type: "string" },
        flowType: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        archyYamlDirectory: { type: "string" },
        yamlText: { type: "string" },
        archyYamlPath: { type: "string" },
        includeQueueMemberCounts: { type: "boolean" },
        priorityReviewThreshold: { type: "integer", minimum: 1, maximum: 25000000 },
        includeMatrix: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_collect_flow_component_matrix",
    description: "Create component-to-flow matrix showing each component and which Architect flows use it.",
    inputSchema: {
      type: "object",
      properties: {
        flowType: { type: "string" },
        flowName: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        archyYamlDirectory: { type: "string" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_export_flow_components_csv",
    description: "Export flow component inventory to CSV with Flow Name, Queues, Skills, Schedules, Data Tables, Data Actions, Prompts, Wrap-up Codes, Priority, and findings.",
    inputSchema: {
      type: "object",
      properties: {
        flowId: { type: "string" },
        flowName: { type: "string" },
        flowType: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        archyYamlDirectory: { type: "string" },
        yamlText: { type: "string" },
        archyYamlPath: { type: "string" },
        includeQueueMemberCounts: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_audit_flow_components",
    description: "Audit collected flow components for findings such as unresolved queues/skills, queues with no members, high ACD priority, and missing/deep YAML limitations.",
    inputSchema: {
      type: "object",
      properties: {
        flowId: { type: "string" },
        flowName: { type: "string" },
        flowType: { type: "string" },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        archyYamlDirectory: { type: "string" },
        yamlText: { type: "string" },
        archyYamlPath: { type: "string" },
        includeQueueMemberCounts: { type: "boolean" },
        priorityReviewThreshold: { type: "integer", minimum: 1, maximum: 25000000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_export_object_inventory_csv",
    description: "Export selected object inventory to CSV in the requested field format.",
    inputSchema: {
      type: "object",
      properties: {
        objectTypes: { type: "array", items: { type: "string" } },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeDetails: { type: "boolean" },
        fields: { type: "array", items: { type: "string" } }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_export_object_inventory_markdown",
    description: "Export selected object inventory to Markdown for documentation or audit evidence.",
    inputSchema: {
      type: "object",
      properties: {
        objectTypes: { type: "array", items: { type: "string" } },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeDetails: { type: "boolean" },
        fields: { type: "array", items: { type: "string" } }
      },
      additionalProperties: false
    }
  },

  {
    name: "gc_blueprint_assessment_map",
    description: "Map the Channel Blueprint Discovery Findings template sections to available MCP tools, evidence types, coverage level, and gaps.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "gc_blueprint_evidence_pack",
    description: "Generate a Channel Blueprint evidence pack combining org summary, audit findings, object lifecycle, flow components, optional conversations, and supplied discovery notes.",
    inputSchema: {
      type: "object",
      properties: {
        assessmentPeriod: { type: "string" },
        preparedFor: { type: "string" },
        preparedBy: { type: "string" },
        objectTypes: { type: "array", items: { type: "string" } },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        staleDays: { type: "integer", minimum: 1, maximum: 3650 },
        includeConversations: { type: "boolean" },
        conversationArgs: { type: "object" },
        includeMetrics: { type: "boolean" },
        metricsArgs: { type: "object" },
        includeFlowComponents: { type: "boolean" },
        archyYamlDirectory: { type: "string" },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        limitFindings: { type: "integer", minimum: 1, maximum: 5000 },
        discoveryNotes: { type: ["object", "string"] }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_metrics_pack",
    description: "Generate Channel Blueprint metrics/statistics: offered, answered, abandoned, transferred, rates, average wait/talk/hold/ACW/handle, channel mix, queue metrics, optional agent metrics, and trends.",
    inputSchema: {
      type: "object",
      properties: {
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        mediaType: { type: "string" },
        mediaTypes: { type: "array", items: { type: "string" } },
        direction: { type: "string" },
        queueIds: { type: "array", items: { type: "string" } },
        queueNames: { type: "array", items: { type: "string" } },
        userIds: { type: "array", items: { type: "string" } },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        includeChannelMetrics: { type: "boolean" },
        includeQueueMetrics: { type: "boolean" },
        includeAgentMetrics: { type: "boolean" },
        includeTrendMetrics: { type: "boolean" },
        trendGranularity: { type: "string" },
        topN: { type: "integer", minimum: 1, maximum: 500 },
        pageSize: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_channel_statistics",
    description: "Return Channel Blueprint channel usage statistics and optional trend rows by media type and direction.",
    inputSchema: {
      type: "object",
      properties: {
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        mediaType: { type: "string" },
        mediaTypes: { type: "array", items: { type: "string" } },
        direction: { type: "string" },
        queueIds: { type: "array", items: { type: "string" } },
        queueNames: { type: "array", items: { type: "string" } },
        includeTrendMetrics: { type: "boolean" },
        trendGranularity: { type: "string" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_queue_statistics",
    description: "Return Channel Blueprint queue-level statistics such as volume, answer/abandon/transfer rates, and average handling metrics.",
    inputSchema: {
      type: "object",
      properties: {
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        mediaType: { type: "string" },
        mediaTypes: { type: "array", items: { type: "string" } },
        direction: { type: "string" },
        queueIds: { type: "array", items: { type: "string" } },
        queueNames: { type: "array", items: { type: "string" } },
        matchType: { type: "string", enum: ["CONTAINS", "EXACT"] },
        topN: { type: "integer", minimum: 1, maximum: 500 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_export_metrics_csv",
    description: "Export Channel Blueprint metrics/statistics rows to CSV for the assessment workbook or evidence appendix.",
    inputSchema: {
      type: "object",
      properties: {
        interval: { type: "string" },
        startDate: { type: "string" },
        endDate: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        mediaType: { type: "string" },
        mediaTypes: { type: "array", items: { type: "string" } },
        direction: { type: "string" },
        queueIds: { type: "array", items: { type: "string" } },
        queueNames: { type: "array", items: { type: "string" } },
        userIds: { type: "array", items: { type: "string" } },
        includeChannelMetrics: { type: "boolean" },
        includeQueueMetrics: { type: "boolean" },
        includeAgentMetrics: { type: "boolean" },
        includeTrendMetrics: { type: "boolean" },
        trendGranularity: { type: "string" },
        topN: { type: "integer", minimum: 1, maximum: 500 }
      },
      additionalProperties: false
    }
  },

  {
    name: "gc_blueprint_member_journey_observations",
    description: "Draft Section 2 Member Journey observations: entry complexity, authentication friction, transfer behaviour, escalation points, and self-service opportunities.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        interval: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        queueId: { type: "string" },
        queueName: { type: "string" },
        mediaType: { type: "string" },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        archyYamlDirectory: { type: "string" },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_agent_team_leader_observations",
    description: "Draft Section 3 Agent & Team Leader observations: manual intervention, knowledge dependency, queue management, escalation behaviour, and hold drivers.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        interval: { type: "string" },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        queueId: { type: "string" },
        queueName: { type: "string" },
        mediaType: { type: "string" },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxQueues: { type: "integer", minimum: 1, maximum: 200 },
        includeRecentAdminActivity: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_channel_routing_observations",
    description: "Draft Section 4 Channel & Routing observations using queues, flows, skills, routing, channel usage, and flow component evidence.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        archyYamlDirectory: { type: "string" },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeQueueMemberCounts: { type: "boolean" },
        includeChannelUsage: { type: "boolean" },
        conversationArgs: { type: "object" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_governance_observations",
    description: "Draft Section 5 Platform Ownership & Governance observations using roles, OAuth clients, object lifecycle, and audit/change activity.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        days: { type: "integer", minimum: 1, maximum: 3650 },
        objectTypes: { type: "array", items: { type: "string" } },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        includeChangeHistory: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_emerging_themes",
    description: "Draft Section 6 Emerging Themes by synthesising recurring patterns from the evidence pack and optional discovery notes.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        maxThemes: { type: "integer", minimum: 1, maximum: 10 },
        includeEvidencePack: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_opportunity_summary",
    description: "Draft Section 7 Opportunity Summary as exploration areas with evidence, potential benefit, priority, and further investigation items.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        maxOpportunities: { type: "integer", minimum: 1, maximum: 20 },
        includeEvidencePack: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_discovery_summary",
    description: "Draft Section 8 Discovery Summary including strengths, challenges, opportunities, design considerations, themes, and narrative.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        maxFindings: { type: "integer", minimum: 1, maximum: 10 },
        maxOpportunities: { type: "integer", minimum: 1, maximum: 20 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_export_markdown",
    description: "Export a Channel Blueprint draft in Markdown aligned to the Word template sections, using platform evidence and optional discovery notes.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        includeAssessorGuidance: { type: "boolean" },
        includeMetrics: { type: "boolean" },
        metricsArgs: { type: "object" },
        includeConversations: { type: "boolean" },
        conversationArgs: { type: "object" },
        includeFlowComponents: { type: "boolean" },
        archyYamlDirectory: { type: "string" },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        limitFindings: { type: "integer", minimum: 1, maximum: 5000 }
      },
      additionalProperties: false
    }
  },
  {
    name: "gc_blueprint_export_docx_payload",
    description: "Return a structured JSON payload that can be used to populate the Channel Blueprint Word template sections.",
    inputSchema: {
      type: "object",
      properties: {
        evidencePack: { type: "object" },
        discoveryNotes: { type: ["object", "string"] },
        includeRawEvidence: { type: "boolean" },
        includeMetrics: { type: "boolean" },
        metricsArgs: { type: "object" },
        includeConversations: { type: "boolean" },
        conversationArgs: { type: "object" },
        includeFlowComponents: { type: "boolean" },
        archyYamlDirectory: { type: "string" },
        maxPages: { type: "integer", minimum: 1, maximum: 500 },
        maxFlows: { type: "integer", minimum: 1, maximum: 500 },
        limitFindings: { type: "integer", minimum: 1, maximum: 5000 }
      },
      additionalProperties: false
    }
  },

];

// MCP handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;

  try {
    let result;

    switch (name) {
      case "gc_catalog":
        result = RESOURCE_CATALOG;
        break;

      case "gc_cache_stats":
        result = cacheStats();
        break;

      case "gc_cache_clear":
        result = cacheClear();
        break;

      case "gc_snapshot_status":
        result = await snapshotStatus();
        break;

      case "gc_snapshot_clear":
        result = await snapshotClearTool();
        break;

      case "gc_health_check":
        result = await gcHealthCheckTool();
        break;

      case "gc_permissions_check":
        result = await gcPermissionsCheckTool(args || {});
        break;

      case "gc_org_summary":
        result = await gcOrgSummaryTool(args || {});
        break;

      case "gc_audit_users":
        result = await gcAuditUsersTool(args || {});
        break;

      case "gc_audit_roles":
        result = await gcAuditRolesTool(args || {});
        break;

      case "gc_audit_queues":
        result = await gcAuditQueuesTool(args || {});
        break;

      case "gc_audit_routing":
        result = await gcAuditRoutingTool(args || {});
        break;

      case "gc_conversation_search":
        result = await gcConversationSearchTool(args || {});
        break;

      case "gc_conversation_detail":
        result = await gcConversationDetailTool(args || {});
        break;

      case "gc_conversation_timeline":
        result = await gcConversationTimelineTool(args || {});
        break;

      case "gc_disconnect_reason_audit":
        result = await gcDisconnectReasonAuditTool(args || {});
        break;

      case "gc_queue_conversation_audit":
        result = await gcQueueConversationAuditTool(args || {});
        break;

      case "gc_audit_report_summary":
        result = await gcAuditReportSummaryTool(args || {});
        break;

      case "gc_audit_export_markdown":
        result = await gcAuditExportMarkdownTool(args || {});
        break;

      case "gc_audit_export_csv":
        result = await gcAuditExportCsvTool(args || {});
        break;

      case "gc_search_queues":
        result = await gcSearchQueuesTool(args || {});
        break;

      case "gc_query_queue_volumes":
        result = await gcQueryQueueVolumesTool(args || {});
        break;

      case "gc_sample_conversations_by_queue":
        result = await gcSampleConversationsByQueueTool(args || {});
        break;

      case "gc_voice_call_quality":
        result = await gcVoiceCallQualityTool(args || {});
        break;

      case "gc_conversation_sentiment":
        result = await gcConversationSentimentTool(args || {});
        break;

      case "gc_conversation_topics":
        result = await gcConversationTopicsTool(args || {});
        break;

      case "gc_search_voice_conversations":
        result = await gcSearchVoiceConversationsTool(args || {});
        break;

      case "gc_conversation_transcript":
        result = await gcConversationTranscriptTool(args || {});
        break;

      case "gc_oauth_clients":
        result = await gcOauthClientsTool(args || {});
        break;

      case "gc_oauth_client_usage":
        result = await gcOauthClientUsageTool(args || {});
        break;

      case "gc_license_users":
        result = await gcLicenseUsersTool(args || {});
        break;

      case "gc_license_usage_summary":
        result = await gcLicenseUsageSummaryTool(args || {});
        break;

      case "gc_api_usage_summary":
        result = await gcApiUsageSummaryTool(args || {});
        break;

      case "gc_subscription_overview":
        result = await gcSubscriptionOverviewTool(args || {});
        break;

      case "gc_billable_usage_report":
        result = await gcBillableUsageReportTool(args || {});
        break;

      case "gc_ai_usage_audit":
        result = await gcAiUsageAuditTool(args || {});
        break;

      case "gc_subscription_usage_audit":
        result = await gcSubscriptionUsageAuditTool(args || {});
        break;

      case "gc_flow_inventory":
        result = await gcFlowInventoryTool(args || {});
        break;

      case "gc_flow_versions":
        result = await gcFlowVersionsTool(args || {});
        break;

      case "gc_flow_component_audit":
        result = await gcFlowComponentAuditTool(args || {});
        break;

      case "gc_audit_flows":
        result = await gcAuditFlowsTool(args || {});
        break;

      case "gc_snapshot_build":
        result = await snapshotBuildTool(args || {});
        break;

      case "gc_list":
        result = await gcListTool(args || {});
        break;

      case "gc_export_csv":
        result = await gcExportCsvTool(args || {});
        break;

      case "gc_search":
        result = await gcSearchTool(args || {});
        break;

      case "gc_user_profile":
        result = await gcUserProfileTool(args || {});
        break;

      // ✅ NEW TOP 5
      case "gc_user_access_summary":
        result = await gcUserAccessSummaryTool(args || {});
        break;

      case "gc_queue_staffing":
        result = await gcQueueStaffingTool(args || {});
        break;

      case "gc_role_impact":
        result = await gcRoleImpactTool(args || {});
        break;

      case "gc_queue_overview":
        result = await gcQueueOverviewTool(args || {});
        break;

      case "gc_user_routing_profile":
        result = await gcUserRoutingProfileTool(args || {});
        break;


      case "gc_object_catalog":
        result = gcObjectCatalogTool(args || {});
        break;

      case "gc_object_inventory":
        result = await gcObjectInventoryTool(args || {});
        break;

      case "gc_collect_all_objects":
        result = await gcCollectAllObjectsTool(args || {});
        break;

      case "gc_object_detail":
        result = await gcObjectDetailTool(args || {});
        break;

      case "gc_object_relationships":
        result = await gcObjectRelationshipsTool(args || {});
        break;

      case "gc_object_change_history":
        result = await gcObjectChangeHistoryTool(args || {});
        break;

      case "gc_audit_recent_admin_activity":
        result = await gcAuditRecentAdminActivityTool(args || {});
        break;

      case "gc_audit_all_objects":
        result = await gcAuditAllObjectsTool(args || {});
        break;

      case "gc_audit_object_lifecycle":
        result = await gcAuditObjectLifecycleTool(args || {});
        break;

      case "gc_audit_stale_objects":
        result = await gcAuditStaleObjectsTool(args || {});
        break;

      case "gc_audit_orphaned_objects":
        result = await gcAuditOrphanedObjectsTool(args || {});
        break;

      case "gc_collect_flow_components":
        result = await gcCollectFlowComponentsTool(args || {});
        break;

      case "gc_collect_flow_component_matrix":
        result = await gcCollectFlowComponentMatrixTool(args || {});
        break;

      case "gc_export_flow_components_csv":
        result = await gcExportFlowComponentsCsvTool(args || {});
        break;

      case "gc_audit_flow_components":
        result = await gcAuditFlowComponentsTool(args || {});
        break;

      case "gc_export_object_inventory_csv":
        result = await gcExportObjectInventoryCsvTool(args || {});
        break;

      case "gc_export_object_inventory_markdown":
        result = await gcExportObjectInventoryMarkdownTool(args || {});
        break;


      case "gc_blueprint_assessment_map":
        result = gcBlueprintAssessmentMapTool(args || {});
        break;

      case "gc_blueprint_evidence_pack":
        result = await gcBlueprintEvidencePackTool(args || {});
        break;

      case "gc_blueprint_metrics_pack":
        result = await gcBlueprintMetricsPackTool(args || {});
        break;

      case "gc_blueprint_channel_statistics":
        result = await gcBlueprintChannelStatisticsTool(args || {});
        break;

      case "gc_blueprint_queue_statistics":
        result = await gcBlueprintQueueStatisticsTool(args || {});
        break;

      case "gc_blueprint_export_metrics_csv":
        result = await gcBlueprintExportMetricsCsvTool(args || {});
        break;

      case "gc_blueprint_member_journey_observations":
        result = await gcBlueprintMemberJourneyObservationsTool(args || {});
        break;

      case "gc_blueprint_agent_team_leader_observations":
        result = await gcBlueprintAgentTeamLeaderObservationsTool(args || {});
        break;

      case "gc_blueprint_channel_routing_observations":
        result = await gcBlueprintChannelRoutingObservationsTool(args || {});
        break;

      case "gc_blueprint_governance_observations":
        result = await gcBlueprintGovernanceObservationsTool(args || {});
        break;

      case "gc_blueprint_emerging_themes":
        result = await gcBlueprintEmergingThemesTool(args || {});
        break;

      case "gc_blueprint_opportunity_summary":
        result = await gcBlueprintOpportunitySummaryTool(args || {});
        break;

      case "gc_blueprint_discovery_summary":
        result = await gcBlueprintDiscoverySummaryTool(args || {});
        break;

      case "gc_blueprint_export_markdown":
        result = await gcBlueprintExportMarkdownTool(args || {});
        break;

      case "gc_blueprint_export_docx_payload":
        result = await gcBlueprintExportDocxPayloadTool(args || {});
        break;

      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: "text",
          text: typeof result === "string" ? result : JSON.stringify(result, null, 2)
        }
      ]
    };
  } catch (err) {
    const message = String(err?.message || err || "Unknown error");
    const payload = {
      ok: false,
      tool: name,
      error: message,
      hint: message.includes("Token error")
        ? "Most likely OAuth credentials or GC_REGION are wrong. Run gc_health_check and confirm the org region, client ID, and client secret."
        : "Run gc_health_check to diagnose the connection, then check Claude MCP logs if needed."
    };

    // Return the real error to Claude instead of throwing an MCP error.
    // Claude Desktop often shows thrown tool errors only as generic "Tool execution failed".
    return {
      isError: true,
      content: [{ type: "text", text: JSON.stringify(payload, null, 2) }]
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);

console.error("[gc-org-audit] MCP server connected (stdio).");
