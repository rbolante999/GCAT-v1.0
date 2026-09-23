import "dotenv/config";
import fs from "node:fs";
import { Parser as Json2csvParser } from "@json2csv/plainjs";

/** =========================
 * ENV + CONSTANTS
 * ========================= */
const RAW_GC_REGION = process.env.GC_REGION ?? process.env.GENESYSCLOUD_REGION;
const RAW_GC_SERVICE_CLIENT_ID = process.env.GC_SERVICE_CLIENT_ID ?? process.env.GENESYSCLOUD_OAUTHCLIENT_ID;
const RAW_GC_SERVICE_CLIENT_SECRET = process.env.GC_SERVICE_CLIENT_SECRET ?? process.env.GENESYSCLOUD_OAUTHCLIENT_SECRET;

function normalizeRegion(value) {
  let v = String(value || "").trim();
  v = v.replace(/^https?:\/\//i, "");
  v = v.replace(/^login\./i, "");
  v = v.replace(/^api\./i, "");
  v = v.split("/")[0];
  return v.replace(/\/+$/g, "");
}

const GC_REGION = normalizeRegion(RAW_GC_REGION);
const GC_SERVICE_CLIENT_ID = String(RAW_GC_SERVICE_CLIENT_ID || "").trim();
const GC_SERVICE_CLIENT_SECRET = String(RAW_GC_SERVICE_CLIENT_SECRET || "").trim();

const {
  EXPORT_PAGE_SIZE = "100",
  EXPORT_MAX_PAGES = "50",
  API_CONCURRENCY_LIMIT = "6",

  TTL_USERS_ALL_MS = String(12 * 60 * 60 * 1000),
  TTL_ROLE_DETAIL_MS = String(6 * 60 * 60 * 1000),
  TTL_ROLE_USERS_MS = String(60 * 60 * 1000),
  TTL_ROLE_GRANTS_MS = String(6 * 60 * 60 * 1000),

  SNAPSHOT_ENABLED = "true",
  SNAPSHOT_TTL_MS = String(6 * 60 * 60 * 1000),
  SNAPSHOT_BUILD_PAGE_SIZE = "200",
  SNAPSHOT_BUILD_MAX_PAGES = "500"
} = process.env;

function must(name, v) {
  if (!v) throw new Error(`Missing env var: ${name}`);
}

must("GC_REGION or GENESYSCLOUD_REGION", GC_REGION);
must("GC_SERVICE_CLIENT_ID or GENESYSCLOUD_OAUTHCLIENT_ID", GC_SERVICE_CLIENT_ID);
must("GC_SERVICE_CLIENT_SECRET or GENESYSCLOUD_OAUTHCLIENT_SECRET", GC_SERVICE_CLIENT_SECRET);

const LOGIN_BASE = `https://login.${GC_REGION}`;
const API_BASE = `https://api.${GC_REGION}`;
const SNAPSHOT_ON = String(SNAPSHOT_ENABLED || "").toLowerCase() === "true";

const TTL = {
  USERS_ALL: Math.max(0, Number(TTL_USERS_ALL_MS) || 0),
  ROLE_DETAIL: Math.max(0, Number(TTL_ROLE_DETAIL_MS) || 0),
  ROLE_USERS: Math.max(0, Number(TTL_ROLE_USERS_MS) || 0),
  ROLE_GRANTS: Math.max(0, Number(TTL_ROLE_GRANTS_MS) || 0)
};

const now = () => Date.now();

/** =========================
 * CACHE + INFLIGHT
 * ========================= */
const CACHE = new Map(); // key -> {value, expiresAt}
const INFLIGHT = new Map(); // key -> Promise

function cacheGet(key) {
  const hit = CACHE.get(key);
  if (!hit) return null;
  if (hit.expiresAt <= now()) {
    CACHE.delete(key);
    return null;
  }
  return hit.value;
}

function cacheSet(key, value, ttlMs) {
  CACHE.set(key, { value, expiresAt: now() + Math.max(0, Number(ttlMs) || 0) });
}

async function cached(key, ttlMs, fn) {
  const hit = cacheGet(key);
  if (hit != null) return hit;

  if (INFLIGHT.has(key)) return INFLIGHT.get(key);

  const p = (async () => {
    const v = await fn();
    cacheSet(key, v, ttlMs);
    return v;
  })();

  INFLIGHT.set(key, p);
  try {
    return await p;
  } finally {
    INFLIGHT.delete(key);
  }
}

/** =========================
 * TOKEN (CLIENT CREDENTIALS)
 * ========================= */
let SERVICE_TOKEN = null;
let SERVICE_TOKEN_INFLIGHT = null;

function tokenValid() {
  if (!SERVICE_TOKEN?.access_token) return false;
  const obtained = Number(SERVICE_TOKEN.obtained_at || 0);
  const expiresMs = Number(SERVICE_TOKEN.expires_in || 0) * 1000;
  return now() < obtained + expiresMs - 60_000;
}

async function getAccessToken() {
  if (tokenValid()) return SERVICE_TOKEN.access_token;
  if (SERVICE_TOKEN_INFLIGHT) return (await SERVICE_TOKEN_INFLIGHT).access_token;

  SERVICE_TOKEN_INFLIGHT = (async () => {
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    const auth = Buffer.from(`${GC_SERVICE_CLIENT_ID}:${GC_SERVICE_CLIENT_SECRET}`).toString("base64");

    const res = await fetch(`${LOGIN_BASE}/oauth/token`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    });

    const txt = await res.text();
    if (!res.ok) throw new Error(`Token error ${res.status}: ${txt}`);

    const json = JSON.parse(txt);
    SERVICE_TOKEN = { ...json, obtained_at: now() };
    return SERVICE_TOKEN;
  })();

  try {
    return (await SERVICE_TOKEN_INFLIGHT).access_token;
  } finally {
    SERVICE_TOKEN_INFLIGHT = null;
  }
}

/** =========================
 * HTTP HELPERS (429 SAFE)
 * ========================= */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseRetryAfterSeconds(res, bodyText) {
  const h = res.headers.get("retry-after");
  if (h && /^\d+$/.test(h)) return Number(h);

  const m = String(bodyText || "").match(/Retry the request in \[(\d+)\] seconds/i);
  if (m && m[1]) return Number(m[1]);

  return null;
}

async function gcGet(path, token) {
  const url = `${API_BASE}${path}`;
  for (let attempt = 1; attempt <= 6; attempt++) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });

    if (res.ok) return res.json();

    const txt = await res.text();
    if (res.status === 429) {
      const retrySec = parseRetryAfterSeconds(res, txt) ?? Math.min(60, 2 ** attempt);
      await sleep((retrySec + 1) * 1000);
      continue;
    }

    throw new Error(`GC GET ${res.status} ${path}: ${txt}`);
  }
  throw new Error(`GC GET retry limit exceeded: ${path}`);
}

async function gcPost(path, token, body) {
  const url = `${API_BASE}${path}`;
  for (let attempt = 1; attempt <= 6; attempt++) {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body || {})
    });

    const txt = await res.text();
    if (res.ok) return txt ? JSON.parse(txt) : {};

    if (res.status === 429) {
      const retrySec = parseRetryAfterSeconds(res, txt) ?? Math.min(60, 2 ** attempt);
      await sleep((retrySec + 1) * 1000);
      continue;
    }

    throw new Error(`GC POST ${res.status} ${path}: ${txt}`);
  }
  throw new Error(`GC POST retry limit exceeded: ${path}`);
}

/** =========================
 * CONCURRENCY
 * ========================= */
async function mapLimit(arr, limit, fn) {
  const items = Array.isArray(arr) ? arr : [];
  const lim = Math.max(1, Number(limit) || 1);
  const out = new Array(items.length);
  let idx = 0;

  async function worker() {
    while (true) {
      const i = idx++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  }

  await Promise.all(Array.from({ length: lim }, worker));
  return out;
}

/** =========================
 * SMALL HELPERS
 * ========================= */
const norm = (s) => String(s || "").toLowerCase();
const matches = (h, n, t) => {
  const H = norm(h);
  const N = norm(n);
  if (!N) return false;
  return t === "EXACT" ? H === N : H.includes(N);
};

function joinLines(values) {
  return (values || [])
    .map((v) => (v == null ? "" : String(v)).trim())
    .filter((v) => v.length > 0)
    .join("\n");
}

function chunk(arr, size) {
  const out = [];
  const s = Math.max(1, Number(size) || 1);
  for (let i = 0; i < (arr || []).length; i += s) out.push(arr.slice(i, i + s));
  return out;
}

function titleize(s) {
  return String(s || "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_\-]+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatPermissionPolicies(policies) {
  if (!Array.isArray(policies)) return "";

  function normPart(x) {
    const s = String(x ?? "").trim();
    if (!s) return "";
    if (s === "*") return "All Permissions";
    return titleize(s);
  }

  function pushLine(lines, domainRaw, entityRaw, actionRaw, effectRaw) {
    const effect = String(effectRaw || "").toLowerCase();
    const isDeny = effect === "deny" || effect === "denied";

    const domain = normPart(domainRaw);
    let entity = normPart(entityRaw);
    let action = normPart(actionRaw);

    if (!domain) return;

    if (!entity && !action) {
      lines.push(isDeny ? `${domain} (Deny)` : domain);
      return;
    }

    if (entity && !action) action = "All Permissions";
    if (!entity && action) entity = "All Permissions";

    const base = [domain, entity, action].filter(Boolean).join(" > ");
    lines.push(isDeny ? `${base} (Deny)` : base);
  }

  const lines = [];

  for (const p of policies) {
    if (!p || typeof p !== "object") continue;

    const effect = p.effect || p.result || "";

    const permKey = p.permission || p.permissionName || p.permissionId || p.key || p.id || "";
    const keyStr = String(permKey || "").trim();
    if (keyStr.includes(":")) {
      const parts = keyStr.split(":").filter((x) => x != null && String(x).trim().length);

      const domain = parts[0] || "";
      let action = "";
      let entity = "";

      if (parts.length === 1) {
        entity = "";
        action = "";
      } else if (parts.length === 2) {
        entity = parts[1];
        action = "*";
      } else {
        action = parts[parts.length - 1];
        entity = parts.slice(1, -1).join(" ");
      }

      pushLine(lines, domain, entity, action, effect);
      continue;
    }

    const domain = p.domain || p.category || p.group || p.permissionDomain || "";
    const entityName = p.entityName || p.entity || p.resourceName || p.subjectName || p.name || "";

    const actionSet = Array.isArray(p.actionSet)
      ? p.actionSet
      : Array.isArray(p.actions)
        ? p.actions
        : Array.isArray(p.operations)
          ? p.operations
          : null;

    if (Array.isArray(actionSet) && actionSet.length) {
      for (const a of actionSet) pushLine(lines, domain, entityName, a, effect);
      continue;
    }

    const action = p.action || p.operation || p.permissionAction || "";
    pushLine(lines, domain, entityName || "*", action || "*", effect);
  }

  const uniq = Array.from(new Set(lines)).sort((a, b) => a.localeCompare(b));
  return joinLines(uniq);
}

function formatPermissionsFromList(perms) {
  const lines = [];
  const arr = Array.isArray(perms) ? perms : [];

  for (const item of arr) {
    const s = typeof item === "string" ? item : (item?.permission || item?.permissionName || item?.id || item?.key || "");
    const keyStr = String(s || "").trim();
    if (!keyStr) continue;

    if (keyStr.includes(":")) {
      const parts = keyStr.split(":").filter((x) => String(x).trim().length);

      const domain = parts[0] || "";
      let entity = "";
      let action = "";

      if (parts.length === 1) {
        entity = "";
        action = "";
      } else if (parts.length === 2) {
        entity = parts[1];
        action = "*";
      } else {
        action = parts[parts.length - 1];
        entity = parts.slice(1, -1).join(" ");
      }

      const dom = titleize(domain);
      const ent = entity === "*" ? "All Permissions" : titleize(entity);
      const act = action === "*" ? "All Permissions" : titleize(action);

      const base = [dom, ent, act].filter(Boolean).join(" > ");
      if (base) lines.push(base);
      continue;
    }

    lines.push(titleize(keyStr));
  }

  const uniq = Array.from(new Set(lines)).sort((a, b) => a.localeCompare(b));
  return joinLines(uniq);
}

function formatPermissionPoliciesSmart(permissionPolicies, permissions) {
  const fromPolicies = formatPermissionPolicies(permissionPolicies || []);
  const hasRichLines = String(fromPolicies || "")
    .split("\n")
    .some((line) => line.includes(" > "));
  if (hasRichLines) return fromPolicies;

  const fromPerms = formatPermissionsFromList(permissions || []);
  return fromPerms || fromPolicies || "";
}

/** =========================
 * RESOURCE CATALOG
 * ========================= */
export const RESOURCE_CATALOG = {
  users: {
    label: "Users",
    fields: ["id", "name", "email", "username", "state", "department", "title", "division.id", "division.name", "roles", "skills", "groups", "queues"],
    defaults: ["id", "name", "email", "state"]
  },
  queues: {
    label: "Queues",
    fields: ["id", "name", "description", "division.id", "division.name", "memberCount", "mediaSettings"],
    defaults: ["id", "name", "description"]
  },
  groups: {
    label: "Groups",
    fields: ["id", "name", "description", "type", "visibility", "owner.id", "owner.name"],
    defaults: ["id", "name", "description"]
  },
  roles: {
    label: "Roles",
    fields: ["id", "name", "description", "permissions", "permissionPolicies", "permissionPoliciesFormatted", "memberCount", "memberIds", "memberUsernames", "memberNames", "subjectGrants"],
    defaults: ["id", "name", "description", "permissionPoliciesFormatted", "memberCount", "memberUsernames"]
  }
};

/** =========================
 * SNAPSHOT STORE (optional)
 * ========================= */
const SNAPSHOT = {
  status: "EMPTY", // EMPTY | BUILDING | READY | FAILED
  startedAt: null,
  finishedAt: null,
  expiresAt: null,
  error: null,
  meta: null,
  data: {}
};

function snapshotIsReady() {
  if (!SNAPSHOT_ON) return false;
  if (SNAPSHOT.status !== "READY") return false;
  if (!SNAPSHOT.expiresAt) return false;
  return new Date(SNAPSHOT.expiresAt).getTime() > now();
}

function snapshotClear() {
  SNAPSHOT.status = "EMPTY";
  SNAPSHOT.startedAt = null;
  SNAPSHOT.finishedAt = null;
  SNAPSHOT.expiresAt = null;
  SNAPSHOT.error = null;
  SNAPSHOT.meta = null;
  SNAPSHOT.data = {};
}

export async function snapshotStatus() {
  return {
    enabled: SNAPSHOT_ON,
    status: SNAPSHOT.status,
    startedAt: SNAPSHOT.startedAt,
    finishedAt: SNAPSHOT.finishedAt,
    expiresAt: SNAPSHOT.expiresAt,
    isReady: snapshotIsReady(),
    error: SNAPSHOT.error,
    meta: SNAPSHOT.meta,
    resources: Object.keys(SNAPSHOT.data || {})
  };
}

export async function snapshotClearTool() {
  snapshotClear();
  return { ok: true };
}

async function fetchAllPages(token, basePath, pageSize = 100, maxPages = 200) {
  const out = [];
  for (let page = 1; page <= maxPages; page++) {
    const joiner = basePath.includes("?") ? "&" : "?";
    const path = `${basePath}${joiner}pageNumber=${page}&pageSize=${pageSize}`;
    const data = await gcGet(path, token);
    const batch = data?.entities ?? [];
    out.push(...batch);
    if (!data?.nextUri || batch.length === 0) break;
  }
  return out;
}

export async function snapshotBuildTool({
  resources = ["users", "queues", "groups", "roles"],
  includeInactiveUsers = false,
  enrichUsers = true,
  enrichRoles = true
} = {}) {
  if (!SNAPSHOT_ON) throw new Error("Snapshot is disabled (SNAPSHOT_ENABLED=false).");
  if (SNAPSHOT.status === "BUILDING") throw new Error("Snapshot build already in progress.");

  const useResources = Array.isArray(resources) && resources.length ? resources : ["users", "queues", "groups", "roles"];
  const pageSize = Math.min(500, Math.max(1, Number(SNAPSHOT_BUILD_PAGE_SIZE) || 200));
  const maxPages = Math.max(1, Number(SNAPSHOT_BUILD_MAX_PAGES) || 500);
  const snapshotTtl = Math.max(60_000, Number(SNAPSHOT_TTL_MS) || 0);

  SNAPSHOT.status = "BUILDING";
  SNAPSHOT.startedAt = new Date().toISOString();
  SNAPSHOT.finishedAt = null;
  SNAPSHOT.expiresAt = null;
  SNAPSHOT.error = null;
  SNAPSHOT.meta = { resources: useResources, includeInactiveUsers, enrichUsers, enrichRoles, pageSize, maxPages };
  SNAPSHOT.data = {};

  try {
    const token = await getAccessToken();
    const conc = Math.min(Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6), 3);

    async function fetchResource(r) {
      if (r === "users") return fetchAllPages(token, "/api/v2/users", pageSize, maxPages);
      if (r === "queues") return fetchAllPages(token, "/api/v2/routing/queues", pageSize, maxPages);
      if (r === "groups") return fetchAllPages(token, "/api/v2/groups", pageSize, maxPages);
      if (r === "roles") return fetchAllPages(token, "/api/v2/authorization/roles", pageSize, maxPages);
      return [];
    }

    for (const r of useResources.map((x) => String(x).toLowerCase())) {
      if (!RESOURCE_CATALOG[r]) continue;

      let entities = await fetchResource(r);

      if (r === "users" && !includeInactiveUsers) {
        entities = entities.filter((u) => String(u?.state || "").toLowerCase() === "active");
      }

      if (r === "users" && enrichUsers) {
        const requested = new Set(["roles", "skills", "groups", "queues"]);
        entities = await mapLimit(entities, conc, async (u) => ({ ...u, ...(await enrichUser(token, u.id, requested)) }));
      }

      if (r === "roles" && enrichRoles) {
        const requested = new Set(["permissions", "permissionPolicies", "permissionPoliciesFormatted", "memberCount", "memberIds", "memberUsernames", "memberNames", "subjectGrants"]);
        entities = await mapLimit(entities, conc, async (role) => ({ ...role, ...(await enrichRole(token, role.id, requested)) }));
      }

      SNAPSHOT.data[r] = entities;
    }

    SNAPSHOT.status = "READY";
    SNAPSHOT.finishedAt = new Date().toISOString();
    SNAPSHOT.expiresAt = new Date(Date.now() + snapshotTtl).toISOString();

    return { ok: true, status: "READY", expiresAt: SNAPSHOT.expiresAt };
  } catch (e) {
    SNAPSHOT.status = "FAILED";
    SNAPSHOT.error = String(e?.message || e);
    SNAPSHOT.finishedAt = new Date().toISOString();
    SNAPSHOT.expiresAt = null;
    throw e;
  }
}

function shouldUseSnapshot(useSnapshot) {
  if (!SNAPSHOT_ON) return false;
  if (!snapshotIsReady()) return false;
  return !!useSnapshot;
}

/** =========================
 * USERS / ROLES ENRICH (live)
 * ========================= */
async function enrichUser(token, userId, requested) {
  const out = {};

  if (requested.has("roles")) {
    try {
      const data = await gcGet(`/api/v2/users/${encodeURIComponent(userId)}/roles`, token);
      const roles = (data?.roles || data?.entities || []).map((r) => r?.name).filter(Boolean);
      out.roles = joinLines(roles);
    } catch (e) {
      out.roles = "";
      out.roles_error = String(e?.message || e);
    }
  }

  if (requested.has("skills")) {
    try {
      const data = await gcGet(`/api/v2/users/${encodeURIComponent(userId)}/routingskills`, token);
      // often includes proficiency; keep as "Name (X)"
      const skills = (data?.entities || [])
        .map((s) => {
          const name = s?.name;
          const prof = s?.proficiency;
          return name ? (prof != null ? `${name} (${prof})` : name) : null;
        })
        .filter(Boolean);
      out.skills = joinLines(skills);
    } catch (e) {
      out.skills = "";
      out.skills_error = String(e?.message || e);
    }
  }

  if (requested.has("groups")) {
    try {
      const data = await gcGet(`/api/v2/users/${encodeURIComponent(userId)}/groups`, token);
      const groups = (data?.entities || []).map((g) => g?.name).filter(Boolean);
      out.groups = joinLines(groups);
    } catch (e) {
      out.groups = "";
      out.groups_error = String(e?.message || e);
    }
  }

  if (requested.has("queues")) {
    try {
      const data = await gcGet(`/api/v2/users/${encodeURIComponent(userId)}/queues`, token);
      const queues = (data?.entities || []).map((q) => q?.name).filter(Boolean);
      out.queues = joinLines(queues);
    } catch (e) {
      out.queues = "";
      out.queues_error = String(e?.message || e);
    }
  }

  return out;
}

async function tryUsersBulk(token, ids) {
  const groups = chunk(ids, 100);
  const out = [];

  for (const g of groups) {
    const data = await gcPost(`/api/v2/users/bulk`, token, { ids: g });
    const entities = Array.isArray(data) ? data : (data?.entities || []);
    out.push(...entities);
  }

  return out;
}

async function getUsersDirectoryMap(token) {
  const key = "users:directory:all";
  const pageSize = 200;
  const maxPages = 500;

  return cached(key, TTL.USERS_ALL, async () => {
    const users = await fetchAllPages(token, "/api/v2/users", pageSize, maxPages);
    const m = {};
    for (const u of users || []) {
      if (u?.id) m[u.id] = { id: u.id, name: u.name, email: u.email, username: u.username };
    }
    return m;
  });
}

async function hydrateUsersByIds(token, ids) {
  if (!ids?.length) return [];
  try {
    const users = await tryUsersBulk(token, ids);
    if (Array.isArray(users) && users.length) return users;
  } catch {
    // fallback
  }
  const dir = await getUsersDirectoryMap(token);
  return ids.map((id) => dir[id]).filter(Boolean);
}

async function enrichRole(token, roleId, requested) {
  const out = {};

  if (requested.has("permissions") || requested.has("permissionPolicies") || requested.has("permissionPoliciesFormatted")) {
    const key = `role:${roleId}:detail:v1`;
    try {
      const role = await cached(key, TTL.ROLE_DETAIL, async () =>
        gcGet(`/api/v2/authorization/roles/${encodeURIComponent(roleId)}`, token)
      );

      if (requested.has("permissions")) out.permissions = role?.permissions ?? [];
      if (requested.has("permissionPolicies")) out.permissionPolicies = role?.permissionPolicies ?? [];
      if (requested.has("permissionPoliciesFormatted")) {
        out.permissionPoliciesFormatted = formatPermissionPoliciesSmart(role?.permissionPolicies ?? [], role?.permissions ?? []);
      }
    } catch (e) {
      if (requested.has("permissions")) out.permissions = [];
      if (requested.has("permissionPolicies")) out.permissionPolicies = [];
      if (requested.has("permissionPoliciesFormatted")) out.permissionPoliciesFormatted = "";
      out.permissions_error = String(e?.message || e);
    }
  }

  if (requested.has("memberIds") || requested.has("memberUsernames") || requested.has("memberNames") || requested.has("memberCount")) {
    try {
      const roleUsers = await fetchAllPages(
        token,
        `/api/v2/authorization/roles/${encodeURIComponent(roleId)}/users`,
        100,
        500
      );

      const ids = (roleUsers || []).map((u) => u?.id).filter(Boolean);

      if (requested.has("memberCount")) out.memberCount = ids.length;
      if (requested.has("memberIds")) out.memberIds = joinLines(ids);

      if (requested.has("memberUsernames") || requested.has("memberNames")) {
        const key = `role:${roleId}:membersCsv`;
        const members = await cached(key, TTL.ROLE_USERS, async () => {
          const fullUsers = await hydrateUsersByIds(token, ids);
          const byId = new Map((fullUsers || []).map((u) => [u?.id, { username: u?.username, name: u?.name }]));

          const usernames = ids.map((id) => byId.get(id)?.username).filter((x) => x && String(x).trim().length);
          const names = ids.map((id) => byId.get(id)?.name).filter((x) => x && String(x).trim().length);

          return { usernames: joinLines(usernames), names: joinLines(names) };
        });

        if (requested.has("memberUsernames")) out.memberUsernames = members?.usernames || "";
        if (requested.has("memberNames")) out.memberNames = members?.names || "";
      }
    } catch (e) {
      if (requested.has("memberCount")) out.memberCount = 0;
      if (requested.has("memberIds")) out.memberIds = "";
      if (requested.has("memberUsernames")) out.memberUsernames = "";
      if (requested.has("memberNames")) out.memberNames = "";
      out.members_error = String(e?.message || e);
    }
  }

  if (requested.has("subjectGrants")) {
    const key = `role:${roleId}:subjectgrants`;
    try {
      out.subjectGrants = await cached(key, TTL.ROLE_GRANTS, async () =>
        fetchAllPages(
          token,
          `/api/v2/authorization/roles/${encodeURIComponent(roleId)}/subjectgrants`,
          100,
          500
        )
      );
    } catch (e) {
      out.subjectGrants = [];
      out.subjectgrants_error = String(e?.message || e);
    }
  }

  return out;
}

/** =========================
 * PUBLIC: CACHE TOOLS
 * ========================= */
export function cacheStats() {
  const t = now();
  let alive = 0;
  let expired = 0;
  for (const [, v] of CACHE.entries()) {
    if (v.expiresAt > t) alive++;
    else expired++;
  }
  return { entriesAlive: alive, entriesExpired: expired, inflight: INFLIGHT.size };
}

export function cacheClear() {
  CACHE.clear();
  INFLIGHT.clear();
  SERVICE_TOKEN = null;
  SERVICE_TOKEN_INFLIGHT = null;
  return { ok: true };
}

function redactValue(value, keep = 4) {
  const s = String(value || "");
  if (!s) return "missing";
  if (s.length <= keep) return "***";
  return `${s.slice(0, keep)}...${s.slice(-keep)}`;
}

function classifyConnectionError(message) {
  const m = String(message || "").toLowerCase();
  if (m.includes("invalid_client") || m.includes("401") || m.includes("403")) {
    return "Check the OAuth client ID/secret, OAuth grant type, and the Genesys Cloud region. If the org is in Australia, use mypurecloud.com.au. If it is US, use mypurecloud.com.";
  }
  if (m.includes("enotfound") || m.includes("getaddrinfo") || m.includes("fetch failed")) {
    return "Check GC_REGION. Use only the domain, for example mypurecloud.com.au, not an invalid URL.";
  }
  if (m.includes("missing env var")) {
    return "Add the required env variables in Claude Desktop config or a .env file.";
  }
  return "Check Claude MCP server logs and the returned error details.";
}

export async function gcHealthCheckTool() {
  const envInfo = {
    GC_REGION: RAW_GC_REGION ? "set" : "missing",
    GENESYSCLOUD_REGION: process.env.GENESYSCLOUD_REGION ? "set" : "missing",
    GC_SERVICE_CLIENT_ID: process.env.GC_SERVICE_CLIENT_ID ? "set" : "missing",
    GENESYSCLOUD_OAUTHCLIENT_ID: process.env.GENESYSCLOUD_OAUTHCLIENT_ID ? "set" : "missing",
    GC_SERVICE_CLIENT_SECRET: process.env.GC_SERVICE_CLIENT_SECRET ? "set" : "missing",
    GENESYSCLOUD_OAUTHCLIENT_SECRET: process.env.GENESYSCLOUD_OAUTHCLIENT_SECRET ? "set" : "missing"
  };

  const result = {
    ok: false,
    nodeVersion: process.version,
    region: {
      raw: RAW_GC_REGION || null,
      normalized: GC_REGION,
      loginBase: LOGIN_BASE,
      apiBase: API_BASE
    },
    credentials: {
      clientId: redactValue(GC_SERVICE_CLIENT_ID),
      clientSecret: GC_SERVICE_CLIENT_SECRET ? "set" : "missing"
    },
    acceptedEnvAliases: [
      "GC_REGION or GENESYSCLOUD_REGION",
      "GC_SERVICE_CLIENT_ID or GENESYSCLOUD_OAUTHCLIENT_ID",
      "GC_SERVICE_CLIENT_SECRET or GENESYSCLOUD_OAUTHCLIENT_SECRET"
    ],
    env: envInfo,
    token: null,
    api: null,
    hint: null
  };

  let token;
  try {
    token = await getAccessToken();
    result.token = { ok: true, preview: redactValue(token, 8) };
  } catch (e) {
    const message = String(e?.message || e);
    result.token = { ok: false, error: message };
    result.hint = classifyConnectionError(message);
    return result;
  }

  try {
    const roles = await gcGet(`/api/v2/authorization/roles?pageSize=1&pageNumber=1`, token);
    result.api = {
      ok: true,
      checkedEndpoint: "/api/v2/authorization/roles?pageSize=1&pageNumber=1",
      returned: Array.isArray(roles?.entities) ? roles.entities.length : null,
      total: roles?.total ?? null
    };
    result.ok = true;
    result.hint = "Connection looks good. Try gc_list with resource=roles or users.";
    return result;
  } catch (e) {
    const message = String(e?.message || e);
    result.api = { ok: false, error: message };
    result.hint = classifyConnectionError(message);
    return result;
  }
}

/** =========================
 * PUBLIC: LIST + EXPORT (optional snapshot)
 * ========================= */
function normalizePagedResponse(data) {
  return {
    pageNumber: data?.pageNumber ?? null,
    pageSize: data?.pageSize ?? null,
    total: data?.total ?? null,
    pageCount: data?.pageCount ?? null,
    nextUri: data?.nextUri ?? null,
    entities: data?.entities ?? []
  };
}

async function fetchUsersPage(token, pageNumber, pageSize) {
  return gcGet(`/api/v2/users?pageSize=${pageSize}&pageNumber=${pageNumber}`, token);
}
async function fetchQueuesPage(token, pageNumber, pageSize) {
  return gcGet(`/api/v2/routing/queues?pageSize=${pageSize}&pageNumber=${pageNumber}`, token);
}
async function fetchGroupsPage(token, pageNumber, pageSize) {
  return gcGet(`/api/v2/groups?pageSize=${pageSize}&pageNumber=${pageNumber}`, token);
}
async function fetchRolesPage(token, pageNumber, pageSize) {
  return gcGet(`/api/v2/authorization/roles?pageSize=${pageSize}&pageNumber=${pageNumber}`, token);
}

export async function gcListTool({
  resource,
  pageNumber = 1,
  pageSize = 50,
  fields = [],
  enrichPreview = false,
  useSnapshot = false,
  includeInactiveUsers = false
} = {}) {
  const r = String(resource || "").toLowerCase();
  if (!RESOURCE_CATALOG[r]) throw new Error(`Unknown resource: ${r}`);

  const pn = Math.max(1, Number(pageNumber || 1));
  const ps = Math.min(500, Math.max(1, Number(pageSize || 50)));
  const requestedFields = new Set(Array.isArray(fields) ? fields.map(String) : []);

  if (shouldUseSnapshot(useSnapshot) && SNAPSHOT.data?.[r]) {
    let all = SNAPSHOT.data[r] || [];
    if (r === "users" && !includeInactiveUsers) {
      all = all.filter((u) => String(u?.state || "").toLowerCase() === "active");
    }

    const total = all.length;
    const pageCount = Math.max(1, Math.ceil(total / ps));
    const start = (pn - 1) * ps;
    const entities = all.slice(start, start + ps);

    return {
      pageNumber: pn,
      pageSize: ps,
      total,
      pageCount,
      nextUri: pn < pageCount ? "(snapshot)" : null,
      entities,
      snapshotUsed: true,
      snapshotExpiresAt: SNAPSHOT.expiresAt
    };
  }

  const token = await getAccessToken();

  let data;
  if (r === "users") data = await fetchUsersPage(token, pn, ps);
  if (r === "queues") data = await fetchQueuesPage(token, pn, ps);
  if (r === "groups") data = await fetchGroupsPage(token, pn, ps);
  if (r === "roles") data = await fetchRolesPage(token, pn, ps);

  const normalized = normalizePagedResponse(data);

  if (r === "users" && enrichPreview && normalized.entities?.length) {
    const needsEnrich = requestedFields.has("roles") || requestedFields.has("skills") || requestedFields.has("groups") || requestedFields.has("queues");
    if (needsEnrich) {
      const conc = Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6);
      normalized.entities = await mapLimit(normalized.entities, conc, async (u) => ({ ...u, ...(await enrichUser(token, u.id, requestedFields)) }));
    }
  }

  if (r === "roles" && enrichPreview && normalized.entities?.length) {
    const needsEnrich =
      requestedFields.has("permissions") ||
      requestedFields.has("permissionPolicies") ||
      requestedFields.has("permissionPoliciesFormatted") ||
      requestedFields.has("memberIds") ||
      requestedFields.has("memberUsernames") ||
      requestedFields.has("memberNames") ||
      requestedFields.has("memberCount") ||
      requestedFields.has("subjectGrants");

    if (needsEnrich) {
      const conc = Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6);
      normalized.entities = await mapLimit(normalized.entities, conc, async (role) => ({ ...role, ...(await enrichRole(token, role.id, requestedFields)) }));
    }
  }

  if (r === "users" && !includeInactiveUsers) {
    normalized.entities = (normalized.entities || []).filter((u) => String(u?.state || "").toLowerCase() === "active");
  }

  return { ...normalized, snapshotUsed: false };
}

function getByPath(obj, path) {
  if (!path) return "";
  const tokens = [];
  const re = /([^.[\]]+)|\[(\d+)\]/g;
  let m;
  while ((m = re.exec(path)) !== null) tokens.push(m[1] ?? m[2]);

  let cur = obj;
  for (const t of tokens) {
    if (cur == null) return "";
    const isIndex = /^\d+$/.test(String(t));
    if (Array.isArray(cur) && !isIndex) {
      cur = cur.map((item) => (item == null ? undefined : item[t]));
      continue;
    }
    cur = cur[t];
  }

  if (cur == null) return "";
  if (Array.isArray(cur)) {
    const flat = cur
      .flat()
      .map((x) => (x == null ? "" : typeof x === "object" ? JSON.stringify(x) : String(x)))
      .filter((x) => x !== "");
    return joinLines(flat);
  }
  if (typeof cur === "object") return JSON.stringify(cur);
  return String(cur);
}

export async function gcExportCsvTool({
  resource,
  fields,
  mode = "page",
  includeInactiveUsers = false,
  pageNumber = 1,
  pageSize = 50,
  useSnapshot = false
} = {}) {
  const r = String(resource || "").toLowerCase();
  const catalog = RESOURCE_CATALOG[r];
  if (!catalog) throw new Error(`Unknown resource: ${r}`);

  const selectedFields = Array.isArray(fields) && fields.length ? fields.map(String) : catalog.defaults;
  const requested = new Set(selectedFields);
  const conc = Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6);

  const pn = Math.max(1, Number(pageNumber || 1));
  const ps = Math.min(500, Math.max(1, Number(pageSize || 50)));

  if (shouldUseSnapshot(useSnapshot) && SNAPSHOT.data?.[r]) {
    let entities = SNAPSHOT.data[r] || [];
    if (r === "users" && !includeInactiveUsers) {
      entities = entities.filter((u) => String(u?.state || "").toLowerCase() === "active");
    }

    if (String(mode).toLowerCase() === "page") {
      const start = (pn - 1) * ps;
      entities = entities.slice(start, start + ps);
    } else if (String(mode).toLowerCase() !== "all") {
      throw new Error("mode must be 'page' or 'all'.");
    }

    const rows = await mapLimit(entities, conc, async (entity) => {
      const row = {};
      for (const f of selectedFields) row[f] = getByPath(entity, f);
      return row;
    });

    const parser = new Json2csvParser({ fields: selectedFields });
    return parser.parse(rows);
  }

  const token = await getAccessToken();
  const maxPages = Math.max(1, Number(EXPORT_MAX_PAGES) || 50);
  const allPageSize = Math.min(500, Math.max(1, Number(EXPORT_PAGE_SIZE) || 100));

  let entities = [];

  async function fetchPage(pageNum, pageSz) {
    if (r === "users") return fetchUsersPage(token, pageNum, pageSz);
    if (r === "queues") return fetchQueuesPage(token, pageNum, pageSz);
    if (r === "groups") return fetchGroupsPage(token, pageNum, pageSz);
    if (r === "roles") return fetchRolesPage(token, pageNum, pageSz);
    return { entities: [] };
  }

  if (String(mode).toLowerCase() === "page") {
    const data = await fetchPage(pn, ps);
    entities = data?.entities ?? [];
  } else if (String(mode).toLowerCase() === "all") {
    for (let page = 1; page <= maxPages; page++) {
      const data = await fetchPage(page, allPageSize);
      const batch = data?.entities ?? [];
      entities.push(...batch);
      if (!data?.nextUri || batch.length === 0) break;
    }
  } else {
    throw new Error("mode must be 'page' or 'all'.");
  }

  if (r === "users" && !includeInactiveUsers) {
    entities = entities.filter((u) => String(u?.state || "").toLowerCase() === "active");
  }

  const rows = await mapLimit(entities, conc, async (entity) => {
    let base = entity;

    if (r === "users") {
      base = { ...entity, ...(await enrichUser(token, entity.id, requested)) };
    }

    if (r === "roles") {
      const needsEnrich =
        requested.has("permissions") ||
        requested.has("permissionPolicies") ||
        requested.has("permissionPoliciesFormatted") ||
        requested.has("memberIds") ||
        requested.has("memberUsernames") ||
        requested.has("memberNames") ||
        requested.has("memberCount") ||
        requested.has("subjectGrants");

      if (needsEnrich) base = { ...entity, ...(await enrichRole(token, entity.id, requested)) };
    }

    const row = {};
    for (const f of selectedFields) row[f] = getByPath(base, f);
    return row;
  });

  const parser = new Json2csvParser({ fields: selectedFields });
  return parser.parse(rows);
}

/** =========================
 * SEARCH (NO SNAPSHOT)
 * ========================= */
async function generalSearch(token, type, query, matchType) {
  const res = await gcPost(`/api/v2/search`, token, {
    query: [{ value: query, type: matchType || "CONTAINS", fields: ["name"] }],
    types: [type]
  });

  const raw = res?.results || res?.entities || res?.hits || [];
  return raw.map((r) => r?.entity || r?.result || r);
}

async function listAllRolesForSearch(token, pageSize = 100, maxPages = 50) {
  const out = [];
  for (let page = 1; page <= maxPages; page++) {
    const data = await gcGet(`/api/v2/authorization/roles?pageSize=${pageSize}&pageNumber=${page}`, token);
    const batch = data?.entities || [];
    out.push(...batch);
    if (!data?.nextUri || batch.length === 0) break;
  }
  return out;
}

export async function gcSearchTool({
  query,
  resources = ["users", "queues", "groups", "roles"],
  matchType = "CONTAINS",
  limit = 25
} = {}) {
  if (!query || !String(query).trim()) throw new Error("gc_search requires a non-empty 'query'");

  const token = await getAccessToken();
  const requested = (resources || []).map((r) => String(r).toLowerCase());

  const results = {};
  const errors = {};
  const conc = Math.min(Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6), 4);

  await mapLimit(requested, conc, async (r) => {
    try {
      if (r === "users") results.users = (await generalSearch(token, "users", query, matchType)).slice(0, limit);
      else if (r === "queues") results.queues = (await generalSearch(token, "queues", query, matchType)).slice(0, limit);
      else if (r === "groups") results.groups = (await generalSearch(token, "groups", query, matchType)).slice(0, limit);
      else if (r === "roles") {
        const all = await listAllRolesForSearch(token);
        const filtered = all.filter((role) => matches(role?.name, query, matchType) || matches(role?.description, query, matchType));
        results.roles = filtered.slice(0, limit);
      } else {
        results[r] = [];
        errors[r] = `Unknown resource '${r}'`;
      }
    } catch (e) {
      results[r] = [];
      errors[r] = String(e?.message || e);
    }
  });

  return { query, matchType, resources: requested, limitPerResource: limit, results, errors: Object.keys(errors).length ? errors : undefined };
}

/** =========================
 * NEW “TOP 5” TOOLS (NO SNAPSHOT)
 * ========================= */

/**
 * 1) gc_user_access_summary
 * - input: userId OR userQuery
 * - returns: summary per user (roles/queues/skills/groups)
 */
export async function gcUserAccessSummaryTool({
  userId,
  userQuery,
  matchType = "CONTAINS",
  limit = 10,
  includeGroups = false
} = {}) {
  const token = await getAccessToken();

  let users = [];
  if (userId) {
    const base = await gcGet(`/api/v2/users/${encodeURIComponent(userId)}`, token);
    users = [base];
  } else {
    const q = String(userQuery || "").trim();
    if (!q) throw new Error("Provide userId OR userQuery");
    users = (await generalSearch(token, "users", q, matchType)).slice(0, Math.min(50, Math.max(1, Number(limit) || 10)));
  }

  const requested = new Set(["roles", "queues", "skills"]);
  if (includeGroups) requested.add("groups");

  const conc = Math.min(Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6), 4);

  const enriched = await mapLimit(users, conc, async (u) => {
    const extra = await enrichUser(token, u.id, requested);
    return {
      id: u.id,
      name: u.name,
      email: u.email,
      username: u.username,
      state: u.state,
      roles: extra.roles || "",
      queues: extra.queues || "",
      skills: extra.skills || "",
      groups: includeGroups ? (extra.groups || "") : undefined,
      errors: Object.keys(extra).some((k) => k.endsWith("_error"))
        ? Object.fromEntries(Object.entries(extra).filter(([k]) => k.endsWith("_error")))
        : undefined
    };
  });

  return {
    matchType,
    count: enriched.length,
    users: enriched
  };
}

/**
 * Helper: resolve queue by name (search API)
 */
async function resolveQueueIdByName(token, queueName, matchType = "CONTAINS") {
  const q = String(queueName || "").trim();
  if (!q) return null;
  const hits = await generalSearch(token, "queues", q, matchType);
  const best = (hits || []).find((x) => x?.id) || null;
  return best?.id || null;
}

/**
 * 2) gc_queue_overview
 * - input: queueId OR queueName
 * - returns: queue config overview (+ optional members count)
 */
export async function gcQueueOverviewTool({
  queueId,
  queueName,
  matchType = "CONTAINS",
  includeMembersCount = true
} = {}) {
  const token = await getAccessToken();

  let qid = queueId;
  if (!qid) {
    qid = await resolveQueueIdByName(token, queueName, matchType);
  }
  if (!qid) throw new Error("Provide queueId OR queueName (must resolve to a queue)");

  const queue = await gcGet(`/api/v2/routing/queues/${encodeURIComponent(qid)}`, token);

  let memberCount = queue?.memberCount;
  if (includeMembersCount && (memberCount == null || Number.isNaN(Number(memberCount)))) {
    try {
      const members = await fetchAllPages(token, `/api/v2/routing/queues/${encodeURIComponent(qid)}/members`, 100, 20);
      memberCount = members.length;
    } catch {
      // ignore
    }
  }

  return {
    id: queue?.id,
    name: queue?.name,
    description: queue?.description,
    division: queue?.division,
    memberCount: includeMembersCount ? (memberCount ?? null) : undefined,
    mediaSettings: queue?.mediaSettings ?? null,
    routingRules: queue?.routingRules ?? null,
    createdDate: queue?.createdDate ?? null,
    modifiedDate: queue?.modifiedDate ?? null
  };
}

/**
 * 3) gc_queue_staffing
 * - input: queueId OR queueName
 * - returns: members (id/name/username/email) + optional per-member routing skills
 */
export async function gcQueueStaffingTool({
  queueId,
  queueName,
  matchType = "CONTAINS",
  limitMembers = 200,
  includeMemberSkills = false
} = {}) {
  const token = await getAccessToken();

  let qid = queueId;
  if (!qid) qid = await resolveQueueIdByName(token, queueName, matchType);
  if (!qid) throw new Error("Provide queueId OR queueName (must resolve to a queue)");

  const queue = await gcGet(`/api/v2/routing/queues/${encodeURIComponent(qid)}`, token);

  const members = await fetchAllPages(token, `/api/v2/routing/queues/${encodeURIComponent(qid)}/members`, 100, 50);

  // normalize member userIds
  const userIds = (members || [])
    .map((m) => m?.member?.id || m?.user?.id || m?.id)
    .filter(Boolean)
    .slice(0, Math.max(1, Math.min(2000, Number(limitMembers) || 200)));

  const fullUsers = await hydrateUsersByIds(token, userIds);
  const byId = new Map((fullUsers || []).map((u) => [u?.id, u]));

  const conc = Math.min(Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6), 4);

  const enrichedMembers = await mapLimit(userIds, conc, async (uid) => {
    const u = byId.get(uid) || { id: uid };
    const out = {
      id: u.id,
      name: u.name,
      username: u.username,
      email: u.email
    };

    if (includeMemberSkills) {
      const extra = await enrichUser(token, uid, new Set(["skills"]));
      out.skills = extra.skills || "";
      if (extra.skills_error) out.skills_error = extra.skills_error;
    }

    return out;
  });

  return {
    queue: { id: queue?.id, name: queue?.name },
    memberCount: userIds.length,
    members: enrichedMembers
  };
}

/**
 * Helper: resolve role id by name
 */
async function resolveRoleIdByName(token, roleName, matchType = "CONTAINS") {
  const all = await listAllRolesForSearch(token, 100, 50);
  const hit = (all || []).find((r) => matches(r?.name, roleName, matchType));
  return hit?.id || null;
}

/**
 * 4) gc_role_impact
 * - input: roleId OR roleName
 * - returns: permissions summary + member list
 */
export async function gcRoleImpactTool({
  roleId,
  roleName,
  matchType = "CONTAINS",
  includeMembers = true,
  membersLimit = 200
} = {}) {
  const token = await getAccessToken();

  let rid = roleId;
  if (!rid) rid = await resolveRoleIdByName(token, roleName, matchType);
  if (!rid) throw new Error("Provide roleId OR roleName (must resolve to a role)");

  const role = await gcGet(`/api/v2/authorization/roles/${encodeURIComponent(rid)}`, token);

  const requested = new Set(["permissionPoliciesFormatted", "memberCount", "memberUsernames", "memberNames"]);
  const extra = await enrichRole(token, rid, requested);

  const out = {
    id: role?.id,
    name: role?.name,
    description: role?.description,
    permissionPoliciesFormatted: extra.permissionPoliciesFormatted || "",
    memberCount: extra.memberCount ?? null,
    memberUsernames: extra.memberUsernames || "",
    memberNames: extra.memberNames || "",
    errors: Object.keys(extra).some((k) => k.endsWith("_error"))
      ? Object.fromEntries(Object.entries(extra).filter(([k]) => k.endsWith("_error")))
      : undefined
  };

  if (includeMembers) {
    // If you want “full member objects”, we can fetch ids and hydrate,
    // but that can be heavy. For now we return names/usernames already.
    out.membersLimit = Math.max(1, Number(membersLimit) || 200);
  }

  return out;
}

/**
 * 5) gc_user_routing_profile
 * - input: userId OR userQuery
 * - returns: routing queues + routing skills (with proficiency) + roles
 */
export async function gcUserRoutingProfileTool({
  userId,
  userQuery,
  matchType = "CONTAINS"
} = {}) {
  const token = await getAccessToken();

  let u = null;
  if (userId) {
    u = await gcGet(`/api/v2/users/${encodeURIComponent(userId)}`, token);
  } else {
    const q = String(userQuery || "").trim();
    if (!q) throw new Error("Provide userId OR userQuery");
    const hits = await generalSearch(token, "users", q, matchType);
    u = (hits || []).find((x) => x?.id) || null;
  }
  if (!u?.id) throw new Error("Unable to resolve user");

  // queues / roles / skills are separate calls; errors are surfaced per field
  const extra = await enrichUser(token, u.id, new Set(["queues", "roles", "skills"]));

  return {
    id: u.id,
    name: u.name,
    email: u.email,
    username: u.username,
    state: u.state,
    queues: extra.queues || "",
    roles: extra.roles || "",
    skills: extra.skills || "",
    errors: Object.keys(extra).some((k) => k.endsWith("_error"))
      ? Object.fromEntries(Object.entries(extra).filter(([k]) => k.endsWith("_error")))
      : undefined
  };
}

/** =========================
 * (KEEP) legacy tool: gc_user_profile
 * ========================= */
export async function gcUserProfileTool({ userId } = {}) {
  if (!userId) throw new Error("userId is required");

  const token = await getAccessToken();
  const base = await gcGet(`/api/v2/users/${encodeURIComponent(userId)}`, token);
  const extra = await enrichUser(token, userId, new Set(["roles", "queues", "skills", "groups"]));
  return { ...base, ...extra };
}

/** =========================
 * ORG AUDIT ENGINE V1
 * Read-only audit helpers and conversation review tools.
 * ========================= */
function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

function csvLineCount(value) {
  return String(value || "")
    .split("\n")
    .map((x) => x.trim())
    .filter(Boolean).length;
}

function compactObject(obj) {
  return Object.fromEntries(Object.entries(obj || {}).filter(([, v]) => v !== undefined));
}

function pushFinding(findings, severity, area, title, detail, recommendation, evidence = {}) {
  findings.push(compactObject({ severity, area, title, detail, recommendation, evidence }));
}

function severityScore(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return 4;
  if (s === "high") return 3;
  if (s === "medium") return 2;
  if (s === "low") return 1;
  return 0;
}

function sortFindings(findings) {
  return safeArray(findings).sort((a, b) => severityScore(b.severity) - severityScore(a.severity) || String(a.area || "").localeCompare(String(b.area || "")));
}

function findingSummary(findings) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of safeArray(findings)) {
    const k = String(f?.severity || "info").toLowerCase();
    if (out[k] == null) out.info += 1;
    else out[k] += 1;
    out.total += 1;
  }
  return out;
}

function toIso(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function defaultInterval(days = 1) {
  const end = new Date();
  const start = new Date(end.getTime() - Math.max(1, Number(days) || 1) * 24 * 60 * 60 * 1000);
  return `${start.toISOString()}/${end.toISOString()}`;
}

function normalizeInterval({ interval, startDate, endDate, days = 1 } = {}) {
  if (interval && String(interval).includes("/")) return String(interval);
  const start = toIso(startDate);
  const end = toIso(endDate) || new Date().toISOString();
  if (start) return `${start}/${end}`;
  return defaultInterval(days);
}

async function fetchAllResource(token, resource, pageSize = 100, maxPages = 20) {
  const r = String(resource || "").toLowerCase();
  if (r === "users") return fetchAllPages(token, "/api/v2/users", pageSize, maxPages);
  if (r === "queues") return fetchAllPages(token, "/api/v2/routing/queues", pageSize, maxPages);
  if (r === "groups") return fetchAllPages(token, "/api/v2/groups", pageSize, maxPages);
  if (r === "roles") return fetchAllPages(token, "/api/v2/authorization/roles", pageSize, maxPages);
  if (r === "divisions") return fetchAllPages(token, "/api/v2/authorization/divisions", pageSize, maxPages);
  if (r === "skills") return fetchAllPages(token, "/api/v2/routing/skills", pageSize, maxPages);
  if (r === "wrapupcodes") return fetchAllPages(token, "/api/v2/routing/wrapupcodes", pageSize, maxPages);
  if (r === "flows") return fetchAllPages(token, "/api/v2/flows", pageSize, maxPages);
  throw new Error(`Unknown audit resource: ${resource}`);
}

async function getPagedTotal(token, path) {
  try {
    const data = await gcGet(`${path}${path.includes("?") ? "&" : "?"}pageSize=1&pageNumber=1`, token);
    return { ok: true, total: data?.total ?? null, pageCount: data?.pageCount ?? null };
  } catch (e) {
    return { ok: false, total: null, error: String(e?.message || e) };
  }
}

function getNameList(value) {
  if (Array.isArray(value)) return value.map((x) => x?.name || x?.id || x).filter(Boolean);
  return String(value || "")
    .split("\n")
    .map((x) => x.trim())
    .filter(Boolean);
}

function hasRiskyPermissionText(text) {
  const s = String(text || "").toLowerCase();
  const patterns = [
    "all permissions",
    "authorization > role",
    "authorization > grant",
    "authorization > oauth",
    "oauth > client",
    "admin",
    "recording > recording > delete",
    "recording > recording > download",
    "routing > queue > edit",
    "routing > queue > delete",
    "telephony > plugin > all permissions",
    "architect > flow > edit",
    "integrations > integration > all permissions"
  ];
  return patterns.some((p) => s.includes(p));
}

async function countQueueMembers(token, queueId) {
  const members = await fetchAllPages(token, `/api/v2/routing/queues/${encodeURIComponent(queueId)}/members`, 100, 100);
  return members.length;
}

function queueMediaSummary(mediaSettings) {
  const settings = mediaSettings || {};
  const out = {};
  for (const [media, cfg] of Object.entries(settings)) {
    if (!cfg || typeof cfg !== "object") continue;
    out[media] = compactObject({
      alertingTimeoutSeconds: cfg.alertingTimeoutSeconds,
      serviceLevel: cfg.serviceLevel,
      serviceLevelPercentage: cfg.serviceLevelPercentage,
      enableAutoAnswer: cfg.enableAutoAnswer,
      mode: cfg.mode
    });
  }
  return out;
}

function extractMetricStats(metricStats) {
  const out = {};
  const assignMetric = (metric, value) => {
    if (!metric) return;
    const v = value?.stats || value || {};
    out[String(metric)] = compactObject({
      count: v?.count,
      min: v?.min,
      max: v?.max,
      sum: v?.sum,
      numerator: v?.numerator,
      denominator: v?.denominator,
      ratio: v?.ratio
    });
  };

  if (Array.isArray(metricStats)) {
    for (const item of metricStats) {
      assignMetric(item?.metric || item?.name, item);
    }
    return out;
  }

  const stats = metricStats || {};
  for (const [metric, value] of Object.entries(stats)) {
    if (value && typeof value === "object" && (value.metric || value.name)) {
      assignMetric(value.metric || value.name, value);
    } else {
      assignMetric(metric, value);
    }
  }
  return out;
}

function extractConversationSegments(conversation) {
  const rows = [];
  for (const p of safeArray(conversation?.participants)) {
    for (const s of safeArray(p?.sessions)) {
      for (const seg of safeArray(s?.segments)) {
        rows.push({
          conversationId: conversation?.conversationId || conversation?.id,
          participantId: p?.participantId || p?.id,
          participantName: p?.participantName || p?.name,
          purpose: p?.purpose,
          userId: p?.userId,
          queueId: seg?.queueId || s?.queueId,
          mediaType: s?.mediaType,
          direction: s?.direction,
          ani: s?.ani,
          dnis: s?.dnis,
          sessionId: s?.sessionId || s?.id,
          segmentStart: seg?.segmentStart,
          segmentEnd: seg?.segmentEnd,
          segmentType: seg?.segmentType,
          disconnectType: seg?.disconnectType,
          wrapUpCode: seg?.wrapUpCode,
          requestedRoutingSkillIds: seg?.requestedRoutingSkillIds,
          requestedLanguageId: seg?.requestedLanguageId
        });
      }
    }
  }
  return rows;
}

function summarizeConversation(conversation) {
  const segments = extractConversationSegments(conversation);
  const disconnectTypes = Array.from(new Set(segments.map((x) => x.disconnectType).filter(Boolean)));
  const queueIds = Array.from(new Set(segments.map((x) => x.queueId).filter(Boolean)));
  const userIds = Array.from(new Set(segments.map((x) => x.userId).filter(Boolean)));
  const wrapUpCodes = Array.from(new Set(segments.map((x) => x.wrapUpCode).filter(Boolean)));
  const mediaTypes = Array.from(new Set(segments.map((x) => x.mediaType).filter(Boolean)));
  const directions = Array.from(new Set(segments.map((x) => x.direction).filter(Boolean)));
  return {
    conversationId: conversation?.conversationId || conversation?.id,
    conversationStart: conversation?.conversationStart,
    conversationEnd: conversation?.conversationEnd,
    mediaTypes,
    directions,
    queueIds,
    userIds,
    disconnectTypes,
    wrapUpCodes,
    participantCount: safeArray(conversation?.participants).length,
    segmentCount: segments.length
  };
}

function buildSegmentPredicates({ queueId, userId, mediaType, direction, disconnectType, wrapUpCode, ani, dnis } = {}) {
  const predicates = [];
  const add = (dimension, value) => {
    if (value != null && String(value).trim()) predicates.push({ dimension, value: String(value).trim() });
  };
  add("queueId", queueId);
  add("userId", userId);
  add("mediaType", mediaType);
  add("direction", direction);
  add("disconnectType", disconnectType);
  add("wrapUpCode", wrapUpCode);
  add("ani", ani);
  add("dnis", dnis);
  return predicates;
}

async function queryConversationDetails(token, {
  interval,
  startDate,
  endDate,
  days = 1,
  pageNumber = 1,
  pageSize = 25,
  order = "desc",
  orderBy = "conversationStart",
  queueId,
  userId,
  mediaType,
  direction,
  disconnectType,
  wrapUpCode,
  ani,
  dnis,
  rawQuery
} = {}) {
  const body = rawQuery && typeof rawQuery === "object" ? { ...rawQuery } : {
    interval: normalizeInterval({ interval, startDate, endDate, days }),
    order,
    orderBy,
    paging: {
      pageSize: Math.min(100, Math.max(1, Number(pageSize) || 25)),
      pageNumber: Math.max(1, Number(pageNumber) || 1)
    }
  };

  const predicates = buildSegmentPredicates({ queueId, userId, mediaType, direction, disconnectType, wrapUpCode, ani, dnis });
  if (!rawQuery && predicates.length) {
    body.segmentFilters = [{ type: "and", predicates }];
  }

  return { query: body, response: await gcPost("/api/v2/analytics/conversations/details/query", token, body) };
}

async function collectConversationDetailPages(token, args = {}) {
  const maxPages = Math.min(20, Math.max(1, Number(args.maxPages) || 3));
  const pageSize = Math.min(100, Math.max(1, Number(args.pageSize) || 50));
  const conversations = [];
  const pageMeta = [];
  let queryBody = null;

  for (let page = 1; page <= maxPages; page++) {
    const { query, response } = await queryConversationDetails(token, { ...args, pageNumber: page, pageSize });
    if (!queryBody) queryBody = query;
    const batch = response?.conversations || [];
    conversations.push(...batch);
    pageMeta.push({ pageNumber: page, count: batch.length, totalHits: response?.totalHits ?? null });
    if (!batch.length || batch.length < pageSize) break;
  }

  return { query: queryBody, pageMeta, conversations };
}

function aggregateConversationFindings(conversations, { longWaitMs = 300000, longAcwMs = 300000 } = {}) {
  const summaries = safeArray(conversations).map(summarizeConversation);
  const disconnectCounts = {};
  const mediaCounts = {};
  const directionCounts = {};
  const queueCounts = {};
  const wrapUpCounts = {};
  const findings = [];

  for (const s of summaries) {
    for (const d of s.disconnectTypes) disconnectCounts[d] = (disconnectCounts[d] || 0) + 1;
    for (const m of s.mediaTypes) mediaCounts[m] = (mediaCounts[m] || 0) + 1;
    for (const d of s.directions) directionCounts[d] = (directionCounts[d] || 0) + 1;
    for (const q of s.queueIds) queueCounts[q] = (queueCounts[q] || 0) + 1;
    for (const w of s.wrapUpCodes) wrapUpCounts[w] = (wrapUpCounts[w] || 0) + 1;

    if (s.disconnectTypes.includes("peer")) {
      pushFinding(findings, "medium", "Conversations", "Peer disconnect detected", `Conversation ${s.conversationId} contains disconnectType=peer.`, "Review the participant timeline to confirm whether the customer, carrier, or remote endpoint ended the interaction.", { conversationId: s.conversationId });
    }
    if (s.queueIds.length > 2) {
      pushFinding(findings, "medium", "Routing", "Multiple queue hops", `Conversation ${s.conversationId} touched ${s.queueIds.length} queues.`, "Review transfer logic and queue routing to reduce unnecessary queue hops.", { conversationId: s.conversationId, queueIds: s.queueIds });
    }
    if (!s.wrapUpCodes.length && s.userIds.length) {
      pushFinding(findings, "low", "Wrap-up", "Agent interaction without visible wrap-up code", `Conversation ${s.conversationId} has user participants but no wrap-up code in returned detail segments.`, "Confirm wrap-up requirements and check whether wrap-up code capture is configured correctly.", { conversationId: s.conversationId });
    }
  }

  return {
    count: summaries.length,
    disconnectCounts,
    mediaCounts,
    directionCounts,
    queueCounts,
    wrapUpCounts,
    findings: sortFindings(findings),
    findingSummary: findingSummary(findings),
    conversations: summaries
  };
}

export async function gcPermissionsCheckTool({ includeOptional = true } = {}) {
  const token = await getAccessToken();
  const checks = [
    { area: "Users", endpoint: "/api/v2/users?pageSize=1&pageNumber=1", method: "GET", permission: "users:user:view" },
    { area: "Roles", endpoint: "/api/v2/authorization/roles?pageSize=1&pageNumber=1", method: "GET", permission: "authorization:role:view" },
    { area: "Queues", endpoint: "/api/v2/routing/queues?pageSize=1&pageNumber=1", method: "GET", permission: "routing:queue:view" },
    { area: "Groups", endpoint: "/api/v2/groups?pageSize=1&pageNumber=1", method: "GET", permission: "groups:group:view" },
    { area: "Divisions", endpoint: "/api/v2/authorization/divisions?pageSize=1&pageNumber=1", method: "GET", permission: "authorization:division:view" },
    { area: "Skills", endpoint: "/api/v2/routing/skills?pageSize=1&pageNumber=1", method: "GET", permission: "routing:skill:view" },
    { area: "Wrap-up codes", endpoint: "/api/v2/routing/wrapupcodes?pageSize=1&pageNumber=1", method: "GET", permission: "routing:wrapupCode:view" },
    { area: "Architect flows", endpoint: "/api/v2/flows?pageSize=1&pageNumber=1", method: "GET", permission: "architect:flow:view" }
  ];

  if (includeOptional) {
    checks.push({
      area: "Conversation details",
      endpoint: "/api/v2/analytics/conversations/details/query",
      method: "POST",
      permission: "analytics:conversationDetail:view",
      body: { interval: defaultInterval(1), paging: { pageSize: 1, pageNumber: 1 }, order: "desc", orderBy: "conversationStart" }
    });
    checks.push({
      area: "Conversation aggregates",
      endpoint: "/api/v2/analytics/conversations/aggregates/query",
      method: "POST",
      permission: "analytics:conversationAggregate:view",
      body: { interval: defaultInterval(1), metrics: ["nOffered"], groupBy: ["mediaType"] }
    });
    checks.push({
      area: "Audit trail",
      endpoint: "/api/v2/audits/query/servicemapping",
      method: "GET",
      permission: "audits:audit:view"
    });
    checks.push({
      area: "License users",
      endpoint: "/api/v2/license/users?pageSize=1&pageNumber=1",
      method: "GET",
      permission: "license:license:view"
    });
    checks.push({
      area: "OAuth clients / API usage",
      endpoint: "/api/v2/oauth/clients?pageSize=1&pageNumber=1",
      method: "GET",
      permission: "oauth:client:view"
    });
  }

  const results = [];
  for (const c of checks) {
    try {
      const response = c.method === "POST" ? await gcPost(c.endpoint, token, c.body || {}) : await gcGet(c.endpoint, token);
      results.push({ area: c.area, ok: true, endpoint: c.endpoint, suggestedPermission: c.permission, returnedKeys: Object.keys(response || {}).slice(0, 10) });
    } catch (e) {
      results.push({ area: c.area, ok: false, endpoint: c.endpoint, suggestedPermission: c.permission, error: String(e?.message || e) });
    }
  }

  return {
    ok: results.every((r) => r.ok),
    checkedAt: new Date().toISOString(),
    region: GC_REGION,
    results,
    missingOrFailed: results.filter((r) => !r.ok)
  };
}

export async function gcOrgSummaryTool({ pageSize = 100, maxPages = 20, includeSamples = false } = {}) {
  const token = await getAccessToken();
  const totals = {
    users: await getPagedTotal(token, "/api/v2/users"),
    queues: await getPagedTotal(token, "/api/v2/routing/queues"),
    roles: await getPagedTotal(token, "/api/v2/authorization/roles"),
    groups: await getPagedTotal(token, "/api/v2/groups"),
    divisions: await getPagedTotal(token, "/api/v2/authorization/divisions"),
    skills: await getPagedTotal(token, "/api/v2/routing/skills"),
    wrapupcodes: await getPagedTotal(token, "/api/v2/routing/wrapupcodes"),
    flows: await getPagedTotal(token, "/api/v2/flows")
  };

  let userStateSample = null;
  let samples = undefined;
  if (includeSamples) {
    const ps = Math.min(500, Math.max(1, Number(pageSize) || 100));
    const mp = Math.min(100, Math.max(1, Number(maxPages) || 20));
    const [users, queues, roles] = await Promise.all([
      fetchAllResource(token, "users", ps, mp).catch((e) => ({ error: String(e?.message || e) })),
      fetchAllResource(token, "queues", ps, Math.min(mp, 5)).catch((e) => ({ error: String(e?.message || e) })),
      fetchAllResource(token, "roles", ps, Math.min(mp, 5)).catch((e) => ({ error: String(e?.message || e) }))
    ]);
    if (Array.isArray(users)) {
      userStateSample = users.reduce((acc, u) => {
        const s = String(u?.state || "unknown").toLowerCase();
        acc[s] = (acc[s] || 0) + 1;
        return acc;
      }, {});
    }
    samples = {
      users: Array.isArray(users) ? users.slice(0, 5).map((u) => ({ id: u.id, name: u.name, email: u.email, state: u.state, division: u.division?.name })) : users,
      queues: Array.isArray(queues) ? queues.slice(0, 5).map((q) => ({ id: q.id, name: q.name, division: q.division?.name, memberCount: q.memberCount })) : queues,
      roles: Array.isArray(roles) ? roles.slice(0, 5).map((r) => ({ id: r.id, name: r.name, description: r.description })) : roles
    };
  }

  return {
    generatedAt: new Date().toISOString(),
    region: GC_REGION,
    totals,
    userStateSample,
    samples
  };
}

export async function gcAuditUsersTool({
  pageSize = 100,
  maxPages = 20,
  includeInactiveUsers = true,
  enrich = true,
  excessiveRoleThreshold = 5,
  limitFindings = 200
} = {}) {
  const token = await getAccessToken();
  let users = await fetchAllResource(token, "users", Math.min(500, Math.max(1, Number(pageSize) || 100)), Math.min(500, Math.max(1, Number(maxPages) || 20)));
  if (!includeInactiveUsers) users = users.filter((u) => String(u?.state || "").toLowerCase() === "active");

  const requested = new Set(["roles", "queues", "skills"]);
  const conc = Math.min(Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6), 4);
  const enriched = enrich ? await mapLimit(users, conc, async (u) => ({ ...u, ...(await enrichUser(token, u.id, requested)) })) : users;
  const findings = [];
  const nameMap = new Map();
  const emailMap = new Map();

  for (const u of enriched) {
    const rolesCount = csvLineCount(u.roles);
    const queuesCount = csvLineCount(u.queues);
    const skillsCount = csvLineCount(u.skills);
    const state = String(u?.state || "").toLowerCase();

    if (!u?.email) pushFinding(findings, "low", "Users", "User missing email", `${u?.name || u?.id} does not have an email value.`, "Confirm whether this is expected for service/test accounts.", { userId: u?.id, username: u?.username });
    if (!u?.division?.id && !u?.division?.name) pushFinding(findings, "medium", "Users", "User missing division", `${u?.name || u?.id} does not show a division in the returned user data.`, "Confirm division assignment and OAuth visibility.", { userId: u?.id });
    if (state && state !== "active" && (rolesCount > 0 || queuesCount > 0)) pushFinding(findings, "high", "Users", "Inactive user still has access/routing assignment", `${u?.name || u?.id} is ${u?.state} with ${rolesCount} roles and ${queuesCount} queues.`, "Review inactive users and remove queue membership or elevated access if no longer required.", { userId: u?.id, rolesCount, queuesCount });
    if (rolesCount >= Number(excessiveRoleThreshold)) pushFinding(findings, "medium", "Access", "User has many roles", `${u?.name || u?.id} has ${rolesCount} roles.`, "Review whether the user has overlapping or excessive access.", { userId: u?.id, rolesCount });
    if (queuesCount > 0 && skillsCount === 0) pushFinding(findings, "medium", "Routing", "Queue member has no routing skills", `${u?.name || u?.id} is assigned to queues but no routing skills were returned.`, "Validate queue routing method; skill-based queues may not route as expected without the required skills.", { userId: u?.id, queuesCount });
    if (rolesCount > 0 && queuesCount === 0 && state === "active") pushFinding(findings, "low", "Access", "Active user has roles but no queues", `${u?.name || u?.id} has roles but no queues.`, "Confirm whether this is an admin/supervisor/non-agent account.", { userId: u?.id, rolesCount });

    const n = norm(u?.name);
    if (n) nameMap.set(n, [...(nameMap.get(n) || []), u]);
    const e = norm(u?.email || u?.username);
    if (e) emailMap.set(e, [...(emailMap.get(e) || []), u]);
  }

  for (const [name, list] of nameMap.entries()) {
    if (list.length > 1) pushFinding(findings, "low", "Users", "Duplicate display name", `The display name '${list[0]?.name || name}' appears ${list.length} times.`, "Confirm whether duplicate names cause reporting or access review ambiguity.", { users: list.map((u) => ({ id: u.id, name: u.name, email: u.email })) });
  }

  const limited = sortFindings(findings).slice(0, Math.max(1, Number(limitFindings) || 200));
  return {
    generatedAt: new Date().toISOString(),
    scannedUsers: enriched.length,
    includeInactiveUsers,
    summary: {
      active: enriched.filter((u) => String(u?.state || "").toLowerCase() === "active").length,
      inactiveOrOther: enriched.filter((u) => String(u?.state || "").toLowerCase() !== "active").length,
      withQueues: enriched.filter((u) => csvLineCount(u.queues) > 0).length,
      withSkills: enriched.filter((u) => csvLineCount(u.skills) > 0).length
    },
    findingSummary: findingSummary(findings),
    findings: limited,
    truncated: findings.length > limited.length
  };
}

export async function gcAuditRolesTool({ pageSize = 100, maxPages = 20, enrich = true, memberCountThreshold = 25, limitFindings = 200 } = {}) {
  const token = await getAccessToken();
  const roles = await fetchAllResource(token, "roles", Math.min(500, Math.max(1, Number(pageSize) || 100)), Math.min(500, Math.max(1, Number(maxPages) || 20)));
  const requested = new Set(["permissionPoliciesFormatted", "memberCount", "memberUsernames", "memberNames"]);
  const conc = Math.min(Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6), 3);
  const enriched = enrich ? await mapLimit(roles, conc, async (r) => ({ ...r, ...(await enrichRole(token, r.id, requested)) })) : roles;
  const findings = [];

  for (const r of enriched) {
    const name = String(r?.name || "");
    const memberCount = Number(r?.memberCount ?? 0);
    const perms = String(r?.permissionPoliciesFormatted || "");
    if (memberCount === 0) pushFinding(findings, "low", "Roles", "Role has no members", `Role '${name}' has no members.`, "Review unused roles and retire if no longer required.", { roleId: r?.id, roleName: name });
    if (memberCount >= Number(memberCountThreshold)) pushFinding(findings, "medium", "Roles", "Role assigned broadly", `Role '${name}' has ${memberCount} members.`, "Review broad role assignment, especially if this is an elevated role.", { roleId: r?.id, roleName: name, memberCount });
    if (/admin|master|super/i.test(name)) pushFinding(findings, "medium", "Roles", "Admin-like role name", `Role '${name}' appears to be an admin/elevated role.`, "Confirm assignment is limited to approved administrators.", { roleId: r?.id, roleName: name, memberCount });
    if (hasRiskyPermissionText(perms)) pushFinding(findings, "high", "Permissions", "Potentially high-risk permissions", `Role '${name}' includes permissions that should be reviewed.`, "Review permissions for least-privilege and confirm business justification.", { roleId: r?.id, roleName: name, memberCount, permissionPreview: perms.split("\n").slice(0, 25) });
  }

  const limited = sortFindings(findings).slice(0, Math.max(1, Number(limitFindings) || 200));
  return {
    generatedAt: new Date().toISOString(),
    scannedRoles: enriched.length,
    summary: {
      withNoMembers: enriched.filter((r) => Number(r?.memberCount ?? 0) === 0).length,
      aboveMemberThreshold: enriched.filter((r) => Number(r?.memberCount ?? 0) >= Number(memberCountThreshold)).length,
      adminLikeNames: enriched.filter((r) => /admin|master|super/i.test(String(r?.name || ""))).length
    },
    findingSummary: findingSummary(findings),
    findings: limited,
    truncated: findings.length > limited.length
  };
}

export async function gcAuditQueuesTool({ pageSize = 100, maxPages = 20, includeMemberCounts = true, limitFindings = 200 } = {}) {
  const token = await getAccessToken();
  const queues = await fetchAllResource(token, "queues", Math.min(500, Math.max(1, Number(pageSize) || 100)), Math.min(500, Math.max(1, Number(maxPages) || 20)));
  const conc = Math.min(Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6), 3);
  const detailed = await mapLimit(queues, conc, async (q) => {
    let detail = q;
    try { detail = await gcGet(`/api/v2/routing/queues/${encodeURIComponent(q.id)}`, token); } catch { /* keep list item */ }
    let memberCount = detail?.memberCount ?? q?.memberCount;
    if (includeMemberCounts && (memberCount == null || Number.isNaN(Number(memberCount)))) {
      try { memberCount = await countQueueMembers(token, q.id); } catch { memberCount = null; }
    }
    return { ...detail, memberCount };
  });

  const findings = [];
  for (const q of detailed) {
    const name = q?.name || q?.id;
    const memberCount = Number(q?.memberCount ?? 0);
    const media = q?.mediaSettings || {};
    if (!q?.division?.id && !q?.division?.name) pushFinding(findings, "medium", "Queues", "Queue missing division", `Queue '${name}' does not show a division in returned data.`, "Confirm queue division assignment and OAuth visibility.", { queueId: q?.id });
    if (memberCount === 0) pushFinding(findings, "high", "Queues", "Queue has no members", `Queue '${name}' has no members.`, "Add trained members or retire/disable routing to this queue.", { queueId: q?.id, queueName: name });
    if (memberCount > 200) pushFinding(findings, "low", "Queues", "Very large queue membership", `Queue '${name}' has ${memberCount} members.`, "Confirm membership is intentional and manageable for reporting/routing.", { queueId: q?.id, memberCount });
    for (const [mediaName, cfg] of Object.entries(media)) {
      const timeout = Number(cfg?.alertingTimeoutSeconds);
      if (timeout && timeout < 5) pushFinding(findings, "medium", "Queues", "Very short alerting timeout", `Queue '${name}' ${mediaName} alerting timeout is ${timeout}s.`, "Confirm agents have enough time to answer before timeout.", { queueId: q?.id, media: mediaName, alertingTimeoutSeconds: timeout });
      if (timeout && timeout > 120) pushFinding(findings, "low", "Queues", "Very long alerting timeout", `Queue '${name}' ${mediaName} alerting timeout is ${timeout}s.`, "Review whether long alerting time delays fallback/routing outcomes.", { queueId: q?.id, media: mediaName, alertingTimeoutSeconds: timeout });
      const sl = Number(cfg?.serviceLevel?.durationMs ?? cfg?.serviceLevel?.duration ?? 0);
      if (sl && sl > 300000) pushFinding(findings, "low", "Queues", "Long service-level target", `Queue '${name}' ${mediaName} service level duration appears high.`, "Confirm target wait time reflects business SLA.", { queueId: q?.id, media: mediaName, serviceLevel: cfg?.serviceLevel });
    }
  }

  const limited = sortFindings(findings).slice(0, Math.max(1, Number(limitFindings) || 200));
  return {
    generatedAt: new Date().toISOString(),
    scannedQueues: detailed.length,
    summary: {
      noMembers: detailed.filter((q) => Number(q?.memberCount ?? 0) === 0).length,
      withVoice: detailed.filter((q) => q?.mediaSettings?.call || q?.mediaSettings?.voice).length,
      withCallback: detailed.filter((q) => q?.mediaSettings?.callback).length,
      mediaSettingsObserved: Array.from(new Set(detailed.flatMap((q) => Object.keys(q?.mediaSettings || {}))))
    },
    queues: detailed.slice(0, 50).map((q) => ({ id: q.id, name: q.name, division: q.division?.name, memberCount: q.memberCount, mediaSettings: queueMediaSummary(q.mediaSettings) })),
    findingSummary: findingSummary(findings),
    findings: limited,
    truncated: findings.length > limited.length
  };
}

export async function gcAuditRoutingTool({ maxQueues = 25, includeMemberSkills = true, memberSampleSize = 20, limitFindings = 200 } = {}) {
  const token = await getAccessToken();
  const queues = (await fetchAllResource(token, "queues", 100, 10)).slice(0, Math.max(1, Number(maxQueues) || 25));
  const findings = [];
  const queueResults = [];
  const conc = Math.min(Math.max(1, Number(API_CONCURRENCY_LIMIT) || 6), 2);

  await mapLimit(queues, conc, async (q) => {
    let members = [];
    try { members = await fetchAllPages(token, `/api/v2/routing/queues/${encodeURIComponent(q.id)}/members`, 100, 20); } catch (e) {
      pushFinding(findings, "medium", "Routing", "Unable to read queue members", `Could not read members for queue '${q.name}'.`, "Check routing:queue:view and division access.", { queueId: q.id, error: String(e?.message || e) });
    }
    const userIds = members.map((m) => m?.member?.id || m?.user?.id || m?.id).filter(Boolean).slice(0, Math.max(1, Number(memberSampleSize) || 20));
    let membersWithSkills = [];
    if (includeMemberSkills && userIds.length) {
      membersWithSkills = await mapLimit(userIds, 3, async (uid) => {
        const extra = await enrichUser(token, uid, new Set(["skills"]));
        return { userId: uid, skillsCount: csvLineCount(extra.skills), skills: extra.skills || "", error: extra.skills_error };
      });
    }
    const noSkillMembers = membersWithSkills.filter((m) => !m.error && m.skillsCount === 0).length;
    if (members.length === 0) pushFinding(findings, "high", "Routing", "Queue has no routable members", `Queue '${q.name}' has no members.`, "Add members or remove this queue from routing flows.", { queueId: q.id });
    if (includeMemberSkills && userIds.length && noSkillMembers === userIds.length) pushFinding(findings, "medium", "Routing", "Sampled members have no skills", `All ${userIds.length} sampled members in queue '${q.name}' returned no routing skills.`, "If this queue uses skill-based routing, validate skill assignment and proficiency.", { queueId: q.id, sampledMembers: userIds.length });
    queueResults.push({ queueId: q.id, queueName: q.name, memberCountObserved: members.length, sampledMembers: userIds.length, sampledMembersWithoutSkills: noSkillMembers });
  });

  const limited = sortFindings(findings).slice(0, Math.max(1, Number(limitFindings) || 200));
  return {
    generatedAt: new Date().toISOString(),
    scannedQueues: queues.length,
    includeMemberSkills,
    queueResults,
    findingSummary: findingSummary(findings),
    findings: limited,
    truncated: findings.length > limited.length
  };
}

export async function gcConversationSearchTool(args = {}) {
  const token = await getAccessToken();
  if (args.conversationId) {
    const detail = await gcGet(`/api/v2/analytics/conversations/${encodeURIComponent(args.conversationId)}/details`, token);
    return { mode: "conversationId", conversation: summarizeConversation(detail), detail };
  }
  const { query, response } = await queryConversationDetails(token, args);
  const conversations = safeArray(response?.conversations).map(summarizeConversation);
  return {
    query,
    totalHits: response?.totalHits ?? null,
    pageNumber: response?.pageNumber ?? query?.paging?.pageNumber ?? null,
    pageSize: response?.pageSize ?? query?.paging?.pageSize ?? null,
    count: conversations.length,
    conversations
  };
}

export async function gcConversationDetailTool({ conversationId, includeRaw = false } = {}) {
  if (!conversationId) throw new Error("conversationId is required");
  const token = await getAccessToken();
  const detail = await gcGet(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`, token);
  const summary = summarizeConversation(detail);
  const timeline = extractConversationSegments(detail).sort((a, b) => String(a.segmentStart || "").localeCompare(String(b.segmentStart || "")));
  return compactObject({ summary, timeline, raw: includeRaw ? detail : undefined });
}

export async function gcConversationTimelineTool({ conversationId } = {}) {
  const detail = await gcConversationDetailTool({ conversationId, includeRaw: false });
  const lines = detail.timeline.map((s, i) => ({
    step: i + 1,
    time: s.segmentStart,
    participant: s.participantName || s.purpose || s.participantId,
    purpose: s.purpose,
    mediaType: s.mediaType,
    direction: s.direction,
    segmentType: s.segmentType,
    queueId: s.queueId,
    userId: s.userId,
    disconnectType: s.disconnectType,
    wrapUpCode: s.wrapUpCode
  }));
  return { summary: detail.summary, timeline: lines };
}

export async function gcDisconnectReasonAuditTool(args = {}) {
  const token = await getAccessToken();
  const collected = await collectConversationDetailPages(token, args);
  const audit = aggregateConversationFindings(collected.conversations, args);
  return {
    generatedAt: new Date().toISOString(),
    interval: collected.query?.interval,
    query: collected.query,
    pages: collected.pageMeta,
    ...audit
  };
}

export async function gcQueueConversationAuditTool({ queueId, queueName, matchType = "CONTAINS", includeAggregateQuery = true, ...args } = {}) {
  const token = await getAccessToken();
  let qid = queueId;
  if (!qid && queueName) qid = await resolveQueueIdByName(token, queueName, matchType);
  if (!qid) throw new Error("Provide queueId OR queueName");
  const queue = await gcGet(`/api/v2/routing/queues/${encodeURIComponent(qid)}`, token).catch(() => ({ id: qid, name: queueName }));
  const collected = await collectConversationDetailPages(token, { ...args, queueId: qid });
  const audit = aggregateConversationFindings(collected.conversations, args);

  let aggregate = undefined;
  if (includeAggregateQuery) {
    const interval = collected.query?.interval || normalizeInterval(args);
    const predicates = [{ dimension: "queueId", value: qid }];
    if (args.mediaType) predicates.push({ dimension: "mediaType", value: String(args.mediaType) });
    try {
      const body = {
        interval,
        groupBy: ["queueId", "mediaType"],
        metrics: ["nOffered", "nTransferred", "tAnswered", "tAbandon", "tWait", "tTalk", "tHeld", "tAcw", "tHandle"],
        filter: { type: "and", predicates }
      };
      const res = await gcPost("/api/v2/analytics/conversations/aggregates/query", token, body);
      aggregate = { query: body, results: safeArray(res?.results).map((r) => ({ group: r.group, metrics: extractMetricStats(r.data?.[0]?.metrics || r.metrics) })) };
    } catch (e) {
      aggregate = { error: String(e?.message || e) };
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    queue: { id: queue?.id || qid, name: queue?.name || queueName },
    interval: collected.query?.interval,
    pages: collected.pageMeta,
    aggregate,
    ...audit
  };
}



/** =========================
 * MAKINGCHATBOTS-INSPIRED INSIGHTS TOOLS (v1.4.0)
 * These keep our gc_* naming and reuse this server's auth/error handling.
 * ========================= */
function countMetricValue(metricObj) {
  const stats = metricObj?.stats || metricObj || {};
  return Number(stats.count ?? stats.sum ?? stats.n ?? 0) || 0;
}

function metricStatsForName(metrics, name) {
  const m = safeArray(metrics).find((x) => x?.metric === name || x?.name === name);
  return m?.stats || m || null;
}

function flattenAggregateMetrics(results = []) {
  return safeArray(results).map((r) => {
    const data = safeArray(r?.data)[0] || r;
    return {
      group: r?.group || {},
      metrics: extractMetricStats(data?.metrics || r?.metrics || [])
    };
  });
}

function recursivelyFindValues(obj, keyMatcher, max = 100) {
  const out = [];
  const seen = new Set();
  function walk(v, path = []) {
    if (out.length >= max || v == null) return;
    if (typeof v !== "object") return;
    if (seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) walk(v[i], path.concat(String(i)));
      return;
    }
    for (const [k, val] of Object.entries(v)) {
      if (keyMatcher(String(k), val, path.concat(k))) out.push({ key: k, path: path.concat(k).join("."), value: val });
      walk(val, path.concat(k));
      if (out.length >= max) return;
    }
  }
  walk(obj);
  return out;
}

function extractMosValues(conversation) {
  const values = [];
  const found = recursivelyFindValues(conversation, (key, val) => {
    const k = key.toLowerCase();
    return k.includes("mos") && (typeof val === "number" || (val && typeof val === "object"));
  }, 200);

  for (const f of found) {
    const v = f.value;
    if (typeof v === "number") values.push({ path: f.path, value: v });
    else if (v && typeof v === "object") {
      for (const candidate of [v.min, v.max, v.avg, v.average, v.value, v.score, v?.stats?.min, v?.stats?.max, v?.stats?.avg, v?.stats?.average]) {
        if (typeof candidate === "number") values.push({ path: f.path, value: candidate });
      }
    }
  }

  // Some detail payloads store metric objects as { metric/name: "...mos...", stats: { min/max }}.
  const metricObjects = recursivelyFindValues(conversation, (key, val) => {
    return val && typeof val === "object" && typeof (val.metric || val.name) === "string" && String(val.metric || val.name).toLowerCase().includes("mos");
  }, 200);
  for (const f of metricObjects) {
    const v = f.value;
    for (const candidate of [v.min, v.max, v.avg, v.average, v.value, v.score, v?.stats?.min, v?.stats?.max, v?.stats?.avg, v?.stats?.average]) {
      if (typeof candidate === "number") values.push({ path: f.path, value: candidate });
    }
  }

  const uniq = [];
  const seen = new Set();
  for (const row of values) {
    const key = `${row.path}:${row.value}`;
    if (!seen.has(key)) { seen.add(key); uniq.push(row); }
  }
  return uniq;
}

function extractSentimentSummary(sta) {
  const found = recursivelyFindValues(sta, (key, val) => {
    const k = key.toLowerCase();
    return (k.includes("sentiment") || k === "score") && (typeof val === "number" || typeof val === "string" || (val && typeof val === "object"));
  }, 200);

  const numericScores = [];
  const labels = [];
  for (const f of found) {
    const v = f.value;
    if (typeof v === "number") numericScores.push({ path: f.path, value: v });
    else if (typeof v === "string" && ["positive", "negative", "neutral", "mixed"].includes(v.toLowerCase())) labels.push({ path: f.path, value: v });
    else if (v && typeof v === "object") {
      for (const candidate of [v.score, v.value, v.sentimentScore, v.overallScore, v?.stats?.sum, v?.stats?.average]) {
        if (typeof candidate === "number") numericScores.push({ path: f.path, value: candidate });
      }
      for (const candidate of [v.label, v.sentiment, v.type]) {
        if (typeof candidate === "string") labels.push({ path: f.path, value: candidate });
      }
    }
  }

  const scores = numericScores.map((x) => x.value).filter((x) => Number.isFinite(x));
  const minScore = scores.length ? Math.min(...scores) : null;
  const maxScore = scores.length ? Math.max(...scores) : null;
  const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : null;
  const interpreted = avgScore == null ? "unknown" : avgScore < -20 ? "negative" : avgScore > 20 ? "positive" : "neutral/mixed";

  return { interpreted, minScore, maxScore, avgScore, scores: numericScores.slice(0, 50), labels: labels.slice(0, 50) };
}

function extractTopicSummary(sta) {
  const rows = [];
  const foundArrays = recursivelyFindValues(sta, (key, val) => {
    const k = key.toLowerCase();
    return k.includes("topic") && Array.isArray(val);
  }, 100);

  for (const f of foundArrays) {
    for (const item of safeArray(f.value)) {
      if (item && typeof item === "object") {
        const name = item.topicName || item.name || item.topic || item.label || item.displayName || item.id;
        if (name) rows.push(compactObject({ sourcePath: f.path, id: item.id || item.topicId, name, confidence: item.confidence, phrase: item.phrase, count: item.count }));
      } else if (typeof item === "string") {
        rows.push({ sourcePath: f.path, name: item });
      }
    }
  }

  // Also find individual objects with topic-like fields.
  const foundObjs = recursivelyFindValues(sta, (key, val) => {
    return val && typeof val === "object" && (val.topicName || val.topicId || val.topic || (typeof val.name === "string" && String(key).toLowerCase().includes("topic")));
  }, 100);
  for (const f of foundObjs) {
    const item = f.value;
    const name = item.topicName || item.name || item.topic || item.label || item.displayName || item.id;
    if (name) rows.push(compactObject({ sourcePath: f.path, id: item.id || item.topicId, name, confidence: item.confidence, phrase: item.phrase, count: item.count }));
  }

  const dedup = [];
  const seen = new Set();
  for (const r of rows) {
    const key = `${r.id || ""}:${r.name || ""}:${r.sourcePath || ""}:${r.phrase || ""}`;
    if (!seen.has(key)) { seen.add(key); dedup.push(r); }
  }
  return dedup.slice(0, 100);
}

function extractTranscriptUtterances(transcriptPayload) {
  const candidates = [];
  const arrays = recursivelyFindValues(transcriptPayload, (key, val) => {
    const k = key.toLowerCase();
    return Array.isArray(val) && ["phrases", "utterances", "transcripts", "segments"].some((x) => k.includes(x));
  }, 50);

  for (const arr of arrays) {
    for (const item of safeArray(arr.value)) {
      if (!item || typeof item !== "object") continue;
      const text = item.text || item.transcript || item.phrase || item.message || item.value;
      if (!text || typeof text !== "string") continue;
      candidates.push(compactObject({
        sourcePath: arr.path,
        startTime: item.startTime || item.start || item.startOffsetMs || item.startOffset,
        endTime: item.endTime || item.end || item.endOffsetMs || item.endOffset,
        speaker: item.speaker || item.participantPurpose || item.participant || item.channel || item.role,
        sentiment: item.sentiment || item.sentimentScore,
        text
      }));
    }
  }

  const seen = new Set();
  const out = [];
  for (const u of candidates) {
    const key = `${u.startTime || ""}:${u.speaker || ""}:${u.text}`;
    if (!seen.has(key)) { seen.add(key); out.push(u); }
  }
  return out;
}

async function queryApiUsageResults(token, clientId, body) {
  const created = await gcPost(`/api/v2/oauth/clients/${encodeURIComponent(clientId)}/usage/query`, token, body);
  const executionId = created?.executionId || created?.id || created?.jobId || created?.transactionId;
  if (!executionId) return { queryCreateResponse: created, note: "Usage query created but no execution/result ID was returned in the response." };

  let last = null;
  for (let attempt = 1; attempt <= 20; attempt++) {
    try {
      last = await gcGet(`/api/v2/oauth/clients/${encodeURIComponent(clientId)}/usage/query/results/${encodeURIComponent(executionId)}`, token);
      const state = String(last?.state || last?.status || "").toLowerCase();
      if (!state || ["complete", "completed", "fulfilled", "succeeded", "success"].includes(state) || last?.results || last?.entities) {
        return { executionId, response: last };
      }
    } catch (e) {
      last = { error: String(e?.message || e) };
    }
    await sleep(Math.min(5000, 500 * attempt));
  }
  return { executionId, lastResponse: last, note: "Timed out waiting for OAuth client usage results." };
}

export async function gcSearchQueuesTool({ name = "*", pageNumber = 1, pageSize = 100 } = {}) {
  const token = await getAccessToken();
  const wildcard = String(name || "*").trim();
  const pn = Math.max(1, Number(pageNumber) || 1);
  const ps = Math.min(500, Math.max(1, Number(pageSize) || 100));

  let queryName = wildcard.replace(/\*/g, "");
  let path = `/api/v2/routing/queues?pageSize=${ps}&pageNumber=${pn}`;
  if (queryName) path += `&name=${encodeURIComponent(queryName)}`;
  const res = await gcGet(path, token);
  let entities = safeArray(res.entities);

  if (wildcard.includes("*")) {
    const pattern = new RegExp("^" + wildcard.split("*").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$", "i");
    entities = entities.filter((q) => pattern.test(q?.name || ""));
  }

  return {
    query: { name: wildcard, pageNumber: pn, pageSize: ps },
    pageNumber: res.pageNumber ?? pn,
    pageSize: res.pageSize ?? ps,
    total: res.total ?? res.totalHits ?? null,
    pageCount: res.pageCount ?? null,
    count: entities.length,
    queues: entities.map((q) => ({ id: q.id, name: q.name, description: q.description, division: q.division?.name, memberCount: q.memberCount }))
  };
}

export async function gcQueryQueueVolumesTool({ queueIds, startDate, endDate, interval, mediaType } = {}) {
  const ids = safeArray(queueIds).map((x) => String(x).trim()).filter(Boolean).slice(0, 300);
  if (!ids.length) throw new Error("queueIds is required and must contain at least one queue ID");
  const token = await getAccessToken();
  const predicates = ids.map((id) => ({ dimension: "queueId", value: id }));
  const body = {
    interval: normalizeInterval({ interval, startDate, endDate, days: 1 }),
    groupBy: ["queueId", "mediaType"],
    metrics: ["nOffered", "tAnswered", "tAbandon", "nTransferred", "tWait", "tTalk", "tHeld", "tAcw", "tHandle"],
    filter: { type: "or", predicates }
  };
  if (mediaType) {
    body.filter = { type: "and", clauses: [body.filter, { type: "and", predicates: [{ dimension: "mediaType", value: String(mediaType) }] }] };
  }
  const res = await gcPost("/api/v2/analytics/conversations/aggregates/query", token, body);
  const rows = flattenAggregateMetrics(res?.results).map((r) => ({
    queueId: r.group?.queueId,
    mediaType: r.group?.mediaType,
    metrics: r.metrics
  }));
  return { query: body, count: rows.length, rows };
}

export async function gcSampleConversationsByQueueTool({ queueId, startDate, endDate, interval, sampleSize = 20, pageSize = 100, mediaType, direction } = {}) {
  if (!queueId) throw new Error("queueId is required");
  const token = await getAccessToken();
  const ps = Math.min(100, Math.max(1, Number(pageSize) || 100));
  const predicates = [{ dimension: "queueId", value: String(queueId) }];
  if (mediaType) predicates.push({ dimension: "mediaType", value: String(mediaType) });
  if (direction) predicates.push({ dimension: "direction", value: String(direction) });
  const { query, response } = await queryConversationDetails(token, {
    rawQuery: {
      interval: normalizeInterval({ interval, startDate, endDate, days: 1 }),
      order: "desc",
      orderBy: "conversationStart",
      paging: { pageSize: ps, pageNumber: 1 },
      segmentFilters: [{ type: "and", predicates }]
    }
  });
  const conversations = safeArray(response?.conversations).slice(0, Math.max(1, Number(sampleSize) || 20));
  return {
    query,
    totalHits: response?.totalHits ?? null,
    returned: conversations.length,
    conversationIds: conversations.map((c) => c.conversationId || c.id).filter(Boolean),
    samples: conversations.map(summarizeConversation)
  };
}

export async function gcVoiceCallQualityTool({ conversationIds, includeRaw = false } = {}) {
  const ids = safeArray(conversationIds).map((x) => String(x).trim()).filter(Boolean).slice(0, 100);
  if (!ids.length) throw new Error("conversationIds is required");
  const token = await getAccessToken();
  const rows = await mapLimit(ids, Math.min(4, Math.max(1, Number(API_CONCURRENCY_LIMIT) || 4)), async (id) => {
    try {
      const detail = await gcGet(`/api/v2/analytics/conversations/${encodeURIComponent(id)}/details`, token);
      const mos = extractMosValues(detail);
      const values = mos.map((m) => m.value).filter((v) => Number.isFinite(v));
      return compactObject({
        conversationId: id,
        mediaTypes: summarizeConversation(detail).mediaTypes,
        minMos: values.length ? Math.min(...values) : null,
        maxMos: values.length ? Math.max(...values) : null,
        mosObserved: mos.slice(0, 50),
        quality: values.length ? (Math.min(...values) < 3.5 ? "poor/degraded" : Math.min(...values) < 4 ? "fair" : "good") : "not found in returned detail payload",
        raw: includeRaw ? detail : undefined
      });
    } catch (e) {
      return { conversationId: id, error: String(e?.message || e) };
    }
  });
  return { count: rows.length, rows };
}

export async function gcConversationSentimentTool({ conversationIds, includeRaw = false } = {}) {
  const ids = safeArray(conversationIds).map((x) => String(x).trim()).filter(Boolean).slice(0, 100);
  if (!ids.length) throw new Error("conversationIds is required");
  const token = await getAccessToken();
  const rows = await mapLimit(ids, Math.min(4, Math.max(1, Number(API_CONCURRENCY_LIMIT) || 4)), async (id) => {
    try {
      const sta = await gcGet(`/api/v2/speechandtextanalytics/conversations/${encodeURIComponent(id)}`, token);
      return compactObject({ conversationId: id, sentiment: extractSentimentSummary(sta), raw: includeRaw ? sta : undefined });
    } catch (e) {
      return { conversationId: id, error: String(e?.message || e), hint: "Requires Speech and Text Analytics data and recording permissions, and transcript/analytics availability for the conversation." };
    }
  });
  return { count: rows.length, rows };
}

export async function gcConversationTopicsTool({ conversationId, includeRaw = false } = {}) {
  if (!conversationId) throw new Error("conversationId is required");
  const token = await getAccessToken();
  const sta = await gcGet(`/api/v2/speechandtextanalytics/conversations/${encodeURIComponent(conversationId)}`, token);
  const topics = extractTopicSummary(sta);
  return compactObject({ conversationId, count: topics.length, topics, raw: includeRaw ? sta : undefined });
}

export async function gcSearchVoiceConversationsTool({ phoneNumber, startDate, endDate, interval, pageNumber = 1, pageSize = 100, direction } = {}) {
  const baseArgs = { interval, startDate, endDate, days: 1, pageNumber, pageSize, mediaType: "voice", direction };
  if (!phoneNumber) return gcConversationSearchTool(baseArgs);

  const byAni = await gcConversationSearchTool({ ...baseArgs, ani: phoneNumber });
  const byDnis = await gcConversationSearchTool({ ...baseArgs, dnis: phoneNumber });
  const byId = new Map();
  for (const c of [...safeArray(byAni.conversations), ...safeArray(byDnis.conversations)]) byId.set(c.conversationId, c);
  return {
    query: { ...baseArgs, phoneNumber, searchedFields: ["ani", "dnis"] },
    count: byId.size,
    totalHits: { ani: byAni.totalHits, dnis: byDnis.totalHits },
    conversations: Array.from(byId.values())
  };
}

export async function gcConversationTranscriptTool({ conversationId, includeRaw = false, maxCommunicationsToTry = 30 } = {}) {
  if (!conversationId) throw new Error("conversationId is required");
  const token = await getAccessToken();
  const recordings = await gcGet(`/api/v2/conversations/${encodeURIComponent(conversationId)}/recordings`, token).catch((e) => ({ error: String(e?.message || e), entities: [] }));
  const detail = await gcGet(`/api/v2/analytics/conversations/${encodeURIComponent(conversationId)}/details`, token).catch(() => null);

  const candidates = new Set();
  for (const r of safeArray(recordings?.entities || recordings)) {
    for (const v of [r.communicationId, r.communication?.id, r.sessionId, r.mediaId, r.id]) if (v) candidates.add(String(v));
  }
  for (const p of safeArray(detail?.participants)) {
    for (const s of safeArray(p?.sessions)) {
      for (const v of [s.sessionId, s.id, s.communicationId]) if (v) candidates.add(String(v));
    }
  }

  const attempts = [];
  let transcriptPayload = null;
  for (const communicationId of Array.from(candidates).slice(0, Math.max(1, Number(maxCommunicationsToTry) || 30))) {
    try {
      const urlResponse = await gcGet(`/api/v2/speechandtextanalytics/conversations/${encodeURIComponent(conversationId)}/communications/${encodeURIComponent(communicationId)}/transcripturl`, token);
      const url = typeof urlResponse === "string" ? urlResponse : (urlResponse.url || urlResponse.transcriptUrl || urlResponse.downloadUrl);
      attempts.push({ communicationId, ok: true, urlReturned: Boolean(url) });
      if (!url) continue;
      const res = await fetch(url);
      const txt = await res.text();
      if (!res.ok) throw new Error(`Transcript URL fetch ${res.status}: ${txt.slice(0, 300)}`);
      transcriptPayload = txt ? JSON.parse(txt) : {};
      break;
    } catch (e) {
      attempts.push({ communicationId, ok: false, error: String(e?.message || e).slice(0, 500) });
    }
  }

  if (!transcriptPayload) {
    return {
      conversationId,
      ok: false,
      message: "Transcript could not be retrieved from the available recording/session communication IDs.",
      candidatesTried: attempts,
      recordingsError: recordings?.error,
      hint: "Requires recording:recording:view and speechAndTextAnalytics:data:view. The conversation must have an available transcript."
    };
  }

  const utterances = extractTranscriptUtterances(transcriptPayload);
  return compactObject({
    conversationId,
    ok: true,
    utteranceCount: utterances.length,
    utterances,
    attempts,
    raw: includeRaw ? transcriptPayload : undefined
  });
}

export async function gcOauthClientsTool({ pageNumber = 1, pageSize = 100, includeRoleNames = true, includeDivisionNames = true } = {}) {
  const token = await getAccessToken();
  const pn = Math.max(1, Number(pageNumber) || 1);
  const ps = Math.min(500, Math.max(1, Number(pageSize) || 100));
  const res = await gcGet(`/api/v2/oauth/clients?pageSize=${ps}&pageNumber=${pn}`, token);
  const clients = safeArray(res.entities);

  let rolesById = new Map();
  let divisionsById = new Map();
  if (includeRoleNames) {
    try { rolesById = new Map((await fetchAllPages(token, "/api/v2/authorization/roles", 100, 100)).map((r) => [r.id, r.name])); } catch {}
  }
  if (includeDivisionNames) {
    try { divisionsById = new Map((await fetchAllPages(token, "/api/v2/authorization/divisions", 100, 100)).map((d) => [d.id, d.name])); } catch {}
  }

  return {
    pageNumber: res.pageNumber ?? pn,
    pageSize: res.pageSize ?? ps,
    total: res.total ?? null,
    pageCount: res.pageCount ?? null,
    count: clients.length,
    clients: clients.map((c) => ({
      id: c.id,
      name: c.name,
      description: c.description,
      authorizedGrantType: c.authorizedGrantType,
      state: c.state,
      roles: safeArray(c.roleIds || c.roles).map((r) => typeof r === "string" ? { id: r, name: rolesById.get(r) } : { id: r.id, name: r.name || rolesById.get(r.id) }),
      divisions: safeArray(c.divisionIds || c.divisions).map((d) => typeof d === "string" ? { id: d, name: divisionsById.get(d) } : { id: d.id, name: d.name || divisionsById.get(d.id) })
    }))
  };
}

export async function gcOauthClientUsageTool({ oauthClientId, startDate, endDate, interval } = {}) {
  if (!oauthClientId) throw new Error("oauthClientId is required");
  const token = await getAccessToken();
  const body = { interval: normalizeInterval({ interval, startDate, endDate, days: 7 }) };
  const result = await queryApiUsageResults(token, oauthClientId, body);
  return { query: body, oauthClientId, ...result };
}


/** =========================
 * SUBSCRIPTION, LICENSE, BILLING + USAGE AUDIT (v1.9.0)
 * ========================= */
function normalizePageArgs(pageNumber = 1, pageSize = 100, maxPageSize = 500) {
  return {
    pn: Math.max(1, Number(pageNumber) || 1),
    ps: Math.min(maxPageSize, Math.max(1, Number(pageSize) || 100))
  };
}

function inferPeriodEndingTimestamp(value) {
  if (value != null && value !== "") return String(value);
  return String(Date.now());
}

function objectEntriesDeep(obj, max = 2000) {
  const rows = [];
  const seen = new Set();
  function walk(v, path = []) {
    if (rows.length >= max || v == null) return;
    if (typeof v !== "object") {
      rows.push({ path: path.join("."), value: v });
      return;
    }
    if (seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) walk(v[i], path.concat(String(i)));
    } else {
      for (const [k, val] of Object.entries(v)) walk(val, path.concat(k));
    }
  }
  walk(obj);
  return rows;
}

function getCollection(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.entities)) return payload.entities;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.items)) return payload.items;
  return payload ? [payload] : [];
}

function extractLicenseName(item) {
  const candidates = [
    item?.license?.name,
    item?.license?.id,
    item?.license?.type,
    item?.licenseDefinition?.name,
    item?.licenseDefinition?.id,
    item?.name,
    item?.licenseName,
    item?.licenseId,
    item?.productName,
    item?.sku,
    item?.type
  ];
  for (const c of candidates) if (c != null && String(c).trim()) return String(c).trim();
  return "Unclassified license";
}

function extractUserIdFromLicenseRow(row) {
  return row?.userId || row?.user?.id || row?.id || row?.subject?.id || row?.user?.userId;
}

function extractLicensesFromUserLicenseRow(row) {
  const direct = [row?.licenses, row?.licenseAssignments, row?.assignedLicenses, row?.products, row?.subscriptions]
    .find((x) => Array.isArray(x));
  if (direct) return direct.map((x) => typeof x === "string" ? { licenseId: x, name: x } : x);
  const one = row?.license || row?.licenseDefinition || row?.licenseId || row?.licenseName || row?.productName || row?.sku;
  if (one) return [typeof one === "string" ? { licenseId: one, name: one } : one];
  return [];
}

function summarizeLicenseRows(rows) {
  const byLicense = new Map();
  const byUser = [];
  for (const row of safeArray(rows)) {
    const userId = extractUserIdFromLicenseRow(row);
    const userName = row?.user?.name || row?.userName || row?.name || row?.username || row?.email;
    const licenses = extractLicensesFromUserLicenseRow(row);
    byUser.push(compactObject({ userId, userName, licenseCount: licenses.length, licenses: licenses.map(extractLicenseName), rawShapeKeys: Object.keys(row || {}).slice(0, 20) }));
    for (const lic of licenses.length ? licenses : [{ name: "Unclassified license" }]) {
      const key = extractLicenseName(lic);
      const cur = byLicense.get(key) || { license: key, users: 0, userIds: [] };
      cur.users += 1;
      if (userId) cur.userIds.push(userId);
      byLicense.set(key, cur);
    }
  }
  return { byLicense: Array.from(byLicense.values()).sort((a,b)=>b.users-a.users), byUser };
}

async function getLicenseUsersPage(token, pageNumber = 1, pageSize = 100) {
  const { pn, ps } = normalizePageArgs(pageNumber, pageSize);
  const path = `/api/v2/license/users?pageSize=${ps}&pageNumber=${pn}`;
  try {
    return await gcGet(path, token);
  } catch (e) {
    // Some orgs/API versions expose this endpoint without pagination parameters.
    if (pn === 1) return await gcGet("/api/v2/license/users", token);
    throw e;
  }
}

async function fetchLicenseUsers(token, pageSize = 100, maxPages = 50) {
  const rows = [];
  let last = null;
  for (let pn = 1; pn <= Math.max(1, Number(maxPages) || 50); pn++) {
    last = await getLicenseUsersPage(token, pn, pageSize);
    const pageRows = getCollection(last);
    rows.push(...pageRows);
    const pageCount = Number(last?.pageCount || 0);
    if (!pageRows.length || (pageCount && pn >= pageCount) || last?.nextUri == null && last?.pageCount && pn >= last.pageCount) break;
    if (!last?.pageCount && pageRows.length < Number(pageSize)) break;
  }
  return { rows, lastResponseKeys: Object.keys(last || {}).slice(0, 20), lastResponseMeta: compactObject({ total: last?.total, pageCount: last?.pageCount, pageNumber: last?.pageNumber, pageSize: last?.pageSize }) };
}

export async function gcLicenseUsersTool({ pageNumber = 1, pageSize = 100, includeRaw = false } = {}) {
  const token = await getAccessToken();
  const res = await getLicenseUsersPage(token, pageNumber, pageSize);
  const rows = getCollection(res);
  return compactObject({
    pageNumber: res?.pageNumber ?? (Number(pageNumber) || 1),
    pageSize: res?.pageSize ?? (Number(pageSize) || 100),
    total: res?.total ?? null,
    pageCount: res?.pageCount ?? null,
    count: rows.length,
    users: rows.map((r) => compactObject({ userId: extractUserIdFromLicenseRow(r), userName: r?.user?.name || r?.userName || r?.name || r?.username || r?.email, licenses: extractLicensesFromUserLicenseRow(r).map(extractLicenseName), rawShapeKeys: Object.keys(r || {}).slice(0, 20) })),
    raw: includeRaw ? res : undefined,
    note: "Uses the Genesys Cloud License Users API when available to list user license assignments."
  });
}

export async function gcLicenseUsageSummaryTool({ pageSize = 100, maxPages = 50, includeUserBreakdown = false } = {}) {
  const token = await getAccessToken();
  const fetched = await fetchLicenseUsers(token, pageSize, maxPages);
  const summary = summarizeLicenseRows(fetched.rows);
  return compactObject({
    generatedAt: new Date().toISOString(),
    scannedRows: fetched.rows.length,
    licenseSummary: summary.byLicense,
    userBreakdown: includeUserBreakdown ? summary.byUser : undefined,
    responseMeta: fetched.lastResponseMeta,
    responseKeys: fetched.lastResponseKeys,
    note: "This is a license assignment summary, not a contractual billing invoice. Validate against Genesys Billing/Usage for billable commitments and overages."
  });
}

function extractApiUsageRows(payload) {
  const rows = [];
  const arrays = recursivelyFindValues(payload, (key, val) => Array.isArray(val) && ["results", "entities", "clients", "requests", "usage"].some((x) => key.toLowerCase().includes(x)), 80);
  for (const arr of arrays) {
    for (const item of safeArray(arr.value)) {
      if (!item || typeof item !== "object") continue;
      const count = item.count ?? item.requestCount ?? item.requests ?? item.numberOfRequests ?? item.total ?? item.value;
      const name = item.name || item.oauthClientName || item.clientName || item.path || item.uri || item.route || item.endpoint || item.apiRequest || item.id;
      if (name != null || count != null) rows.push(compactObject({ sourcePath: arr.path, name, id: item.id || item.clientId || item.oauthClientId, method: item.method || item.httpMethod, path: item.path || item.uri || item.endpoint, count: Number(count) || count, percentage: item.percentage || item.percent || item.percentageOfRequests, statusCode: item.statusCode || item.status }));
    }
  }
  const scalars = objectEntriesDeep(payload, 500).filter((x) => /count|requests|usage/i.test(x.path) && (typeof x.value === "number" || /^\d+$/.test(String(x.value))));
  for (const s of scalars.slice(0, 100)) rows.push({ sourcePath: s.path, count: Number(s.value), name: s.path.split(".").slice(-2).join(".") });
  return rows;
}

export async function gcApiUsageSummaryTool({ oauthClientIds, startDate, endDate, interval, maxClients = 25, topN = 25, includeRaw = false } = {}) {
  const token = await getAccessToken();
  let ids = safeArray(oauthClientIds).map((x) => String(x).trim()).filter(Boolean);
  let clients = [];
  if (!ids.length) {
    const clientRes = await gcOauthClientsTool({ pageSize: Math.min(500, Math.max(1, Number(maxClients) || 25)), includeRoleNames: false, includeDivisionNames: false });
    clients = safeArray(clientRes.clients).slice(0, Math.max(1, Number(maxClients) || 25));
    ids = clients.map((c) => c.id).filter(Boolean);
  }
  const clientNameById = new Map(safeArray(clients).map((c) => [c.id, c.name]));
  const body = { interval: normalizeInterval({ interval, startDate, endDate, days: 30 }) };
  const rows = [];
  for (const id of ids.slice(0, Math.max(1, Number(maxClients) || 25))) {
    try {
      const result = await queryApiUsageResults(token, id, body);
      const usageRows = extractApiUsageRows(result.response || result.lastResponse || result.queryCreateResponse || result);
      rows.push({ oauthClientId: id, oauthClientName: clientNameById.get(id), ok: true, rowCount: usageRows.length, usageRows: usageRows.slice(0, Math.max(1, Number(topN) || 25)), raw: includeRaw ? result : undefined });
    } catch (e) {
      rows.push({ oauthClientId: id, oauthClientName: clientNameById.get(id), ok: false, error: String(e?.message || e) });
    }
  }
  const totals = rows.map((r) => ({ oauthClientId: r.oauthClientId, oauthClientName: r.oauthClientName, ok: r.ok, observedRequestCount: safeArray(r.usageRows).reduce((sum, x) => sum + (Number(x.count) || 0), 0), error: r.error })).sort((a,b)=>(b.observedRequestCount||0)-(a.observedRequestCount||0));
  return { generatedAt: new Date().toISOString(), query: body, scannedClients: ids.length, returnedClients: rows.length, totals, rows, note: "API usage visibility depends on Genesys API Usage permissions and daily aggregation availability. Current-day usage may not be included." };
}

export async function gcSubscriptionOverviewTool({ periodEndingTimestamp, includeRaw = false } = {}) {
  const token = await getAccessToken();
  const ts = inferPeriodEndingTimestamp(periodEndingTimestamp);
  const path = `/api/v2/billing/subscriptionoverview?periodEndingTimestamp=${encodeURIComponent(ts)}`;
  try {
    const res = await gcGet(path, token);
    const usageCandidates = objectEntriesDeep(res, 1000).filter((x) => /usage|subscription|license|invoice|rate|commit|balance|overage|token|ai|storage|api|transcription|byoc/i.test(x.path));
    return compactObject({ ok: true, periodEndingTimestamp: ts, endpoint: path, extractedSignals: usageCandidates.slice(0, 250), raw: includeRaw ? res : undefined, note: "This endpoint may be restricted/internal in some orgs. Treat output as best-effort and validate against the Genesys Billing UI." });
  } catch (e) {
    return { ok: false, periodEndingTimestamp: ts, endpoint: path, error: String(e?.message || e), note: "Billing subscription overview may not be available to customer OAuth clients in all orgs. Validate in Genesys Billing and Usage UI or with partner billing APIs if applicable." };
  }
}

export async function gcBillableUsageReportTool({ startDate, endDate, includeRaw = false } = {}) {
  const token = await getAccessToken();
  const params = new URLSearchParams();
  if (startDate) params.set("startDate", String(startDate));
  if (endDate) params.set("endDate", String(endDate));
  const path = `/api/v2/billing/reports/billableusage${params.toString() ? `?${params.toString()}` : ""}`;
  try {
    const res = await gcGet(path, token);
    const usageSignals = objectEntriesDeep(res, 1000).filter((x) => /usage|bill|charge|license|concurrent|commit|overage|quantity|subscription|api|ai|token|storage|byoc|transcription/i.test(x.path));
    return compactObject({ ok: true, endpoint: path, extractedSignals: usageSignals.slice(0, 300), raw: includeRaw ? res : undefined, note: "Best-effort billable usage report. Endpoint coverage and fields vary by org/account type." });
  } catch (e) {
    return { ok: false, endpoint: path, error: String(e?.message || e), note: "Billable usage report may require billing permissions, may vary by org type, and may not expose committed license counts. Validate against official Billing and Usage UI." };
  }
}

export async function gcAiUsageAuditTool({ periodEndingTimestamp, includeRaw = false } = {}) {
  const overview = await gcSubscriptionOverviewTool({ periodEndingTimestamp, includeRaw: true });
  const raw = overview.raw || overview;
  const aiSignals = objectEntriesDeep(raw, 2000).filter((x) => /ai|token|copilot|agentassist|agent.assist|bot|predictive|knowledge|speech|text|transcript|sentiment|topic|virtual|automation/i.test(x.path) || /ai|token|copilot|agent assist|bot|transcript|speech|sentiment|topic/i.test(String(x.value || "")));
  return compactObject({ ok: overview.ok, generatedAt: new Date().toISOString(), periodEndingTimestamp: overview.periodEndingTimestamp, signalCount: aiSignals.length, aiUsageSignals: aiSignals.slice(0, 300), raw: includeRaw ? raw : undefined, note: "AI Experience and token usage are billing/fair-use concepts. This tool extracts visible AI/token-related signals from available billing/subscription data; validate final usage in Genesys Billing and Usage." , upstreamError: overview.ok ? undefined : overview.error });
}

export async function gcSubscriptionUsageAuditTool({ days = 30, includeLicenseUsage = true, includeApiUsage = true, includeBillingUsage = true, includeAiUsage = true, maxClients = 25, includeRaw = false } = {}) {
  const out = { generatedAt: new Date().toISOString(), days, scope: { includeLicenseUsage, includeApiUsage, includeBillingUsage, includeAiUsage } };
  const end = new Date();
  const start = new Date(end.getTime() - Math.max(1, Number(days) || 30) * 24 * 60 * 60 * 1000);
  const interval = `${start.toISOString()}/${end.toISOString()}`;
  if (includeLicenseUsage) out.licenseUsage = await gcLicenseUsageSummaryTool({ includeUserBreakdown: false }).catch((e) => ({ ok: false, error: String(e?.message || e) }));
  if (includeApiUsage) out.apiUsage = await gcApiUsageSummaryTool({ interval, maxClients, includeRaw }).catch((e) => ({ ok: false, error: String(e?.message || e) }));
  if (includeBillingUsage) {
    out.subscriptionOverview = await gcSubscriptionOverviewTool({ includeRaw }).catch((e) => ({ ok: false, error: String(e?.message || e) }));
    out.billableUsageReport = await gcBillableUsageReportTool({ startDate: start.toISOString().slice(0,10), endDate: end.toISOString().slice(0,10), includeRaw }).catch((e) => ({ ok: false, error: String(e?.message || e) }));
  }
  if (includeAiUsage) out.aiUsage = await gcAiUsageAuditTool({ includeRaw }).catch((e) => ({ ok: false, error: String(e?.message || e) }));

  const findings = [];
  for (const l of safeArray(out.licenseUsage?.licenseSummary)) {
    if (l.users === 0) pushFinding(findings, "low", "Licensing", "License with no assigned users", `${l.license} has no observed assigned users.`, "Validate whether this license/subscription is still required or is only contractually committed.", { license: l.license });
  }
  for (const c of safeArray(out.apiUsage?.totals).slice(0, 10)) {
    if ((Number(c.observedRequestCount) || 0) > 0) pushFinding(findings, "info", "API Usage", "OAuth client API usage observed", `${c.oauthClientName || c.oauthClientId} has observed API usage in the selected interval.`, "Review high-usage OAuth clients and endpoints against integration purpose and API fair-use expectations.", c);
  }
  if (out.subscriptionOverview?.ok === false) pushFinding(findings, "low", "Billing", "Subscription overview unavailable", "The subscription overview endpoint was not available to this OAuth client/org.", "Use the Genesys Billing and Usage UI or partner billing APIs where applicable for contractual billing data.", { error: out.subscriptionOverview.error });

  out.findings = sortFindings(findings);
  out.findingSummary = findingSummary(findings);
  out.note = "Combines license assignment, API usage, billing/subscription, and AI usage signals where available. Billing data access varies by org/account type and permissions.";
  return out;
}


/** =========================
 * ARCHITECT FLOW COMPONENT AUDIT (v1.5.0)
 * ========================= */
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const ROUTING_LINE_RE = /(transfer\s*to\s*acd|transferToAcd|acd|queue|routing\s*skill|language\s*skill|skill|priority|preferred\s*agent|agent\s*score|bullseye|screen\s*pop|wrapup|wrap-up)/i;

function stringSet(values) {
  return Array.from(new Set(safeArray(values).map((x) => String(x || "").trim()).filter(Boolean)));
}

function sanitizeFlowFileName(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "")
    .trim();
}

function previewValue(value, max = 240) {
  const s = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return String(s || "").replace(/\s+/g, " ").slice(0, max);
}

function classifyComponentPath(path) {
  const p = String(path || "").toLowerCase();
  if (p.includes("language") && p.includes("skill")) return "languageSkill";
  if (p.includes("skill")) return "skill";
  if (p.includes("queue") || p.includes("acd")) return "queue";
  if (p.includes("priority")) return "priority";
  if (p.includes("preferred") && p.includes("agent")) return "preferredAgent";
  if (p.includes("agent") && p.includes("score")) return "agentScore";
  if (p.includes("bullseye")) return "bullseye";
  if (p.includes("wrapup") || p.includes("wrap-up")) return "wrapup";
  return null;
}

function collectObjectRoutingReferences(value, path = "$", refs = [], depth = 0) {
  if (depth > 24 || value == null) return refs;

  if (Array.isArray(value)) {
    value.slice(0, 5000).forEach((item, i) => collectObjectRoutingReferences(item, `${path}[${i}]`, refs, depth + 1));
    return refs;
  }

  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      const kind = classifyComponentPath(childPath);
      if (kind && (typeof child !== "object" || child == null)) {
        refs.push({ kind, source: "apiObject", path: childPath, value: String(child ?? "") });
      }
      collectObjectRoutingReferences(child, childPath, refs, depth + 1);
    }
    return refs;
  }

  if (typeof value === "string") {
    const kind = classifyComponentPath(path);
    if (kind || ROUTING_LINE_RE.test(value)) {
      refs.push({ kind: kind || "routingText", source: "apiObject", path, value: previewValue(value) });
    }
  }

  return refs;
}

function extractYamlRoutingLines(text) {
  const lines = String(text || "").split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!ROUTING_LINE_RE.test(raw)) continue;
    const before = lines.slice(Math.max(0, i - 2), i).map((x) => x.trim()).filter(Boolean);
    const after = lines.slice(i + 1, Math.min(lines.length, i + 3)).map((x) => x.trim()).filter(Boolean);
    const line = raw.trim();
    out.push({ lineNumber: i + 1, line, context: [...before, line, ...after].join(" | ") });
  }
  return out;
}

function extractPriorityReferencesFromText(text) {
  const out = [];
  const lines = String(text || "").split(/\r?\n/);
  const patterns = [
    /\bpriority\b\s*[:=]\s*("[^"]+"|'[^']+'|[-+]?\d+|[^\s,#}]+)/i,
    /\bpriority\b[^\n\r-+0-9]{0,80}([-+]?\d+)/i
  ];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/priority/i.test(line)) continue;
    let value = null;
    for (const re of patterns) {
      const m = line.match(re);
      if (m) {
        value = String(m[1] || "").replace(/^['"]|['"]$/g, "");
        break;
      }
    }
    out.push({ lineNumber: i + 1, value, expression: value && !/^[-+]?\d+$/.test(value), line: line.trim() });
  }
  return out;
}

function extractIdsFromText(text) {
  return stringSet(String(text || "").match(UUID_RE) || []);
}

function matchNamedResourcesInText(text, resources, kind, maxMatches = 200) {
  const s = norm(text);
  const matchesOut = [];
  for (const r of safeArray(resources)) {
    const name = String(r?.name || "").trim();
    const id = String(r?.id || "").trim();
    if (!name && !id) continue;
    const nameHit = name && s.includes(norm(name));
    const idHit = id && s.includes(norm(id));
    if (nameHit || idHit) {
      matchesOut.push({ kind, id: id || null, name: name || null, matchType: idHit ? "id" : "name" });
      if (matchesOut.length >= maxMatches) break;
    }
  }
  return matchesOut;
}

function dedupeResourceMatches(items) {
  const seen = new Set();
  const out = [];
  for (const item of safeArray(items)) {
    const key = `${item.kind}|${item.id || ""}|${norm(item.name)}|${item.matchType || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function tryReadYamlInput({ yamlText, archyYamlPath, maxBytes = 5_000_000 } = {}) {
  if (yamlText && String(yamlText).trim()) {
    return { source: "yamlText", text: String(yamlText), filePath: null, error: null };
  }
  if (!archyYamlPath) return { source: null, text: "", filePath: null, error: null };

  const filePath = String(archyYamlPath);
  try {
    if (!fs.existsSync(filePath)) return { source: "archyYamlPath", text: "", filePath, error: `YAML file not found: ${filePath}` };
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return { source: "archyYamlPath", text: "", filePath, error: `Path is not a file: ${filePath}` };
    if (stat.size > maxBytes) return { source: "archyYamlPath", text: "", filePath, error: `YAML file is too large (${stat.size} bytes). Max is ${maxBytes}.` };
    return { source: "archyYamlPath", text: fs.readFileSync(filePath, "utf8"), filePath, error: null };
  } catch (e) {
    return { source: "archyYamlPath", text: "", filePath, error: String(e?.message || e) };
  }
}

function findYamlFiles(dir, maxFiles = 500) {
  if (!dir) return [];
  const root = String(dir);
  const out = [];
  function walk(d, depth = 0) {
    if (depth > 4 || out.length >= maxFiles) return;
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const ent of entries) {
      if (out.length >= maxFiles) break;
      const p = `${d}${d.endsWith("\\") || d.endsWith("/") ? "" : "/"}${ent.name}`;
      if (ent.isDirectory()) walk(p, depth + 1);
      else if (/\.(ya?ml)$/i.test(ent.name)) out.push(p);
    }
  }
  if (fs.existsSync(root)) walk(root, 0);
  return out;
}

function findYamlForFlow(flow, directory, maxFiles = 500) {
  const files = findYamlFiles(directory, maxFiles);
  if (!files.length) return null;
  const flowNameKey = sanitizeFlowFileName(flow?.name);
  const flowId = String(flow?.id || "").toLowerCase();

  let best = null;
  for (const file of files) {
    const fileKey = sanitizeFlowFileName(file.split(/[\\/]/).pop());
    if (flowNameKey && fileKey.includes(flowNameKey)) return file;
    if (flowId && file.toLowerCase().includes(flowId)) return file;
    if (!best && flowNameKey) {
      try {
        const head = fs.readFileSync(file, "utf8").slice(0, 20000);
        if (sanitizeFlowFileName(head).includes(flowNameKey)) best = file;
      } catch {}
    }
  }
  return best;
}

function summarizeFlow(flow) {
  return compactObject({
    id: flow?.id,
    name: flow?.name,
    type: flow?.type,
    description: flow?.description,
    division: flow?.division?.name || flow?.division?.id,
    publishedVersion: flow?.publishedVersion?.version || flow?.publishedVersion,
    checkedInVersion: flow?.checkedInVersion?.version || flow?.checkedInVersion,
    savedVersion: flow?.savedVersion?.version || flow?.savedVersion,
    state: flow?.state,
    createdDate: flow?.createdDate,
    modifiedDate: flow?.modifiedDate
  });
}

async function fetchFlows(token, { pageSize = 100, maxPages = 20, flowType, flowName, matchType = "CONTAINS" } = {}) {
  const flows = await fetchAllPages(token, "/api/v2/flows", Math.min(500, Math.max(1, Number(pageSize) || 100)), Math.max(1, Number(maxPages) || 20));
  return flows.filter((f) => {
    const typeOk = !flowType || norm(f?.type) === norm(flowType);
    const nameOk = !flowName || matches(f?.name, flowName, matchType);
    return typeOk && nameOk;
  });
}

async function resolveFlow(token, { flowId, flowName, matchType = "CONTAINS" } = {}) {
  if (flowId) {
    const detail = await gcGet(`/api/v2/flows/${encodeURIComponent(flowId)}`, token);
    return { flow: detail, candidates: [detail] };
  }
  if (!flowName) throw new Error("Provide flowId or flowName.");
  const candidates = await fetchFlows(token, { pageSize: 100, maxPages: 50, flowName, matchType });
  if (!candidates.length) throw new Error(`No flow found matching '${flowName}'.`);
  const flow = matchType === "EXACT" ? candidates[0] : candidates.sort((a, b) => String(a.name || "").length - String(b.name || "").length)[0];
  const detail = await gcGet(`/api/v2/flows/${encodeURIComponent(flow.id)}`, token);
  return { flow: detail, candidates };
}

async function getQueueMemberCount(token, queueId) {
  try {
    const data = await gcGet(`/api/v2/routing/queues/${encodeURIComponent(queueId)}/members?pageSize=1&pageNumber=1`, token);
    return data?.total ?? data?.entities?.length ?? null;
  } catch (e) {
    return null;
  }
}

async function auditFlowComponentsFromSources(token, { flow, flowDetail, yamlText, yamlSource, includeQueueMemberCounts = true, priorityReviewThreshold = 500 } = {}) {
  const queues = await fetchAllResource(token, "queues", 200, 500);
  const skills = await fetchAllResource(token, "skills", 200, 500);
  const queueById = new Map(queues.map((q) => [String(q.id || "").toLowerCase(), q]));
  const skillById = new Map(skills.map((x) => [String(x.id || "").toLowerCase(), x]));

  const apiRefs = flowDetail ? collectObjectRoutingReferences(flowDetail) : [];
  const apiText = JSON.stringify(flowDetail || {});
  const yamlLines = yamlText ? extractYamlRoutingLines(yamlText) : [];
  const priorityRefs = [
    ...extractPriorityReferencesFromText(apiText).map((x) => ({ ...x, source: "apiObject" })),
    ...extractPriorityReferencesFromText(yamlText || "").map((x) => ({ ...x, source: yamlSource || "yaml" }))
  ];

  const searchableText = [apiText, yamlText || "", ...apiRefs.map((r) => `${r.path} ${r.value}`), ...yamlLines.map((l) => `${l.line} ${l.context}`)].join("\n");
  const ids = extractIdsFromText(searchableText);

  const idMatches = [];
  const unresolvedIds = [];
  for (const id of ids) {
    const key = id.toLowerCase();
    if (queueById.has(key)) idMatches.push({ kind: "queue", id, name: queueById.get(key)?.name, matchType: "id" });
    else if (skillById.has(key)) idMatches.push({ kind: "skill", id, name: skillById.get(key)?.name, matchType: "id" });
    else unresolvedIds.push(id);
  }

  const queueMatches = dedupeResourceMatches([
    ...idMatches.filter((x) => x.kind === "queue"),
    ...matchNamedResourcesInText(searchableText, queues, "queue", 500)
  ]);
  const skillMatches = dedupeResourceMatches([
    ...idMatches.filter((x) => x.kind === "skill"),
    ...matchNamedResourcesInText(searchableText, skills, "skill", 500)
  ]);

  const queueDetails = await mapLimit(queueMatches, Math.min(3, Math.max(1, Number(API_CONCURRENCY_LIMIT) || 3)), async (m) => {
    const q = m.id ? queueById.get(String(m.id).toLowerCase()) : safeArray(queues).find((x) => norm(x.name) === norm(m.name));
    const memberCount = includeQueueMemberCounts && q?.id ? await getQueueMemberCount(token, q.id) : undefined;
    return compactObject({
      id: q?.id || m.id || null,
      name: q?.name || m.name || null,
      division: q?.division?.name || q?.division?.id,
      matchType: m.matchType,
      resolved: Boolean(q),
      memberCount
    });
  });

  const skillDetails = skillMatches.map((m) => {
    const sk = m.id ? skillById.get(String(m.id).toLowerCase()) : safeArray(skills).find((x) => norm(x.name) === norm(m.name));
    return compactObject({ id: sk?.id || m.id || null, name: sk?.name || m.name || null, matchType: m.matchType, resolved: Boolean(sk) });
  });

  const findings = [];
  const flowName = flow?.name || flowDetail?.name || "Selected flow";
  if (!yamlText) {
    pushFinding(findings, "info", "Flows", "Deep flow YAML not provided", `${flowName} was scanned using available API metadata only. Transfer-to-ACD action internals may require Archy YAML export for full queue/skill/priority detection.`, "Export the flow to YAML using Archy or Architect export and rerun gc_flow_component_audit with archyYamlPath or yamlText.", { flowId: flow?.id });
  }
  if (queueDetails.length === 0 && skillDetails.length === 0 && priorityRefs.length === 0) {
    pushFinding(findings, "low", "Flows", "No routing components detected", `${flowName} did not expose queue, skill, or priority references in the scanned source.`, "For inbound/in-queue flows, provide Archy YAML to perform deep action-level analysis.", { flowId: flow?.id });
  }
  for (const q of queueDetails) {
    if (!q.resolved) pushFinding(findings, "high", "Flows", "Flow references unresolved queue", `${flowName} appears to reference queue '${q.name || q.id}', but it was not found in the live queue inventory.`, "Confirm whether the queue was renamed/deleted, or update the Architect Transfer to ACD action.", { flowId: flow?.id, queue: q });
    if (q.resolved && q.memberCount === 0) pushFinding(findings, "high", "Flows", "Flow routes to queue with no members", `${flowName} appears to route to queue '${q.name}', but the queue has no members.`, "Add queue members or remove the queue from the flow routing path.", { flowId: flow?.id, queueId: q.id, queueName: q.name });
  }
  for (const sk of skillDetails) {
    if (!sk.resolved) pushFinding(findings, "medium", "Flows", "Flow references unresolved skill", `${flowName} appears to reference skill '${sk.name || sk.id}', but it was not found in the live skill inventory.`, "Confirm whether the skill was renamed/deleted, or update the Architect Transfer to ACD action.", { flowId: flow?.id, skill: sk });
  }
  for (const p of priorityRefs) {
    const raw = String(p.value ?? "").trim();
    const num = /^[-+]?\d+$/.test(raw) ? Number(raw) : null;
    if (num != null && Math.abs(num) > Math.max(1, Number(priorityReviewThreshold) || 500)) {
      pushFinding(findings, "medium", "Flows", "High static ACD priority", `${flowName} contains static priority ${num}, which is above the review threshold ${priorityReviewThreshold}.`, "Confirm that this priority value is intentional and documented because high priority can significantly change queue ordering.", { flowId: flow?.id, priority: num, source: p.source, lineNumber: p.lineNumber });
    } else if (raw && p.expression) {
      pushFinding(findings, "info", "Flows", "Expression-based ACD priority", `${flowName} contains an expression-based priority value '${raw}'.`, "Review the expression logic and confirm expected queue positioning behavior.", { flowId: flow?.id, priority: raw, source: p.source, lineNumber: p.lineNumber });
    }
  }

  const languageSkillLines = yamlLines.filter((l) => /language\s*skill|languageSkill/i.test(l.context));
  const preferredAgentLines = yamlLines.filter((l) => /preferred\s*agent|agent\s*score/i.test(l.context));

  return {
    flow: summarizeFlow(flow || flowDetail || {}),
    sources: compactObject({
      apiObjectScanned: Boolean(flowDetail),
      yamlScanned: Boolean(yamlText),
      yamlSource: yamlSource || undefined,
      routingLinesDetected: yamlLines.length,
      apiReferencesDetected: apiRefs.length,
      unresolvedUuidCount: unresolvedIds.length
    }),
    components: {
      queues: queueDetails,
      skills: skillDetails,
      priorities: priorityRefs,
      languageSkillLines: languageSkillLines.slice(0, 50),
      preferredAgentLines: preferredAgentLines.slice(0, 50),
      routingLines: yamlLines.slice(0, 100),
      apiReferences: apiRefs.slice(0, 100)
    },
    findings: sortFindings(findings),
    findingSummary: findingSummary(findings),
    unresolvedIds: unresolvedIds.slice(0, 100)
  };
}

export async function gcFlowInventoryTool({ pageSize = 100, maxPages = 20, flowType, flowName, matchType = "CONTAINS", includeDetails = false } = {}) {
  const token = await getAccessToken();
  const flows = await fetchFlows(token, { pageSize, maxPages, flowType, flowName, matchType });
  const conc = Math.min(4, Math.max(1, Number(API_CONCURRENCY_LIMIT) || 4));
  const entities = includeDetails
    ? await mapLimit(flows, conc, async (f) => summarizeFlow(await gcGet(`/api/v2/flows/${encodeURIComponent(f.id)}`, token)))
    : flows.map(summarizeFlow);
  return { ok: true, count: entities.length, filters: compactObject({ flowType, flowName, matchType, pageSize, maxPages, includeDetails }), flows: entities };
}

export async function gcFlowVersionsTool({ flowId, flowName, matchType = "CONTAINS" } = {}) {
  const token = await getAccessToken();
  const { flow, candidates } = await resolveFlow(token, { flowId, flowName, matchType });
  const response = await gcGet(`/api/v2/flows/${encodeURIComponent(flow.id)}/versions`, token);
  return {
    ok: true,
    flow: summarizeFlow(flow),
    candidates: candidates.length > 1 ? candidates.map(summarizeFlow).slice(0, 25) : undefined,
    versions: response?.entities || response,
    total: response?.total ?? (response?.entities ? response.entities.length : null)
  };
}

export async function gcFlowComponentAuditTool({
  flowId,
  flowName,
  matchType = "CONTAINS",
  yamlText,
  archyYamlPath,
  includeQueueMemberCounts = true,
  priorityReviewThreshold = 500
} = {}) {
  const token = await getAccessToken();
  const { flow, candidates } = await resolveFlow(token, { flowId, flowName, matchType });
  const yaml = tryReadYamlInput({ yamlText, archyYamlPath });
  if (yaml.error) throw new Error(yaml.error);
  const audit = await auditFlowComponentsFromSources(token, {
    flow,
    flowDetail: flow,
    yamlText: yaml.text,
    yamlSource: yaml.filePath || yaml.source,
    includeQueueMemberCounts,
    priorityReviewThreshold
  });
  return {
    ok: true,
    candidates: candidates.length > 1 ? candidates.map(summarizeFlow).slice(0, 25) : undefined,
    ...audit
  };
}

export async function gcAuditFlowsTool({
  pageSize = 100,
  maxPages = 5,
  maxFlows = 25,
  flowType,
  flowName,
  matchType = "CONTAINS",
  archyYamlDirectory,
  includeQueueMemberCounts = false,
  priorityReviewThreshold = 500,
  limitFindings = 300
} = {}) {
  const token = await getAccessToken();
  const flows = (await fetchFlows(token, { pageSize, maxPages, flowType, flowName, matchType })).slice(0, Math.max(1, Number(maxFlows) || 25));
  const findings = [];
  const audits = [];

  for (const f of flows) {
    const detail = await gcGet(`/api/v2/flows/${encodeURIComponent(f.id)}`, token);
    const yamlPath = archyYamlDirectory ? findYamlForFlow(detail, archyYamlDirectory) : null;
    const yaml = yamlPath ? tryReadYamlInput({ archyYamlPath: yamlPath }) : { text: "", filePath: null, source: null, error: null };
    const audit = await auditFlowComponentsFromSources(token, {
      flow: detail,
      flowDetail: detail,
      yamlText: yaml.text,
      yamlSource: yaml.filePath || yaml.source,
      includeQueueMemberCounts,
      priorityReviewThreshold
    });
    audits.push(audit);
    findings.push(...safeArray(audit.findings));
  }

  const sorted = sortFindings(findings).slice(0, Math.max(1, Number(limitFindings) || 300));
  return {
    ok: true,
    scannedFlows: audits.length,
    filters: compactObject({ pageSize, maxPages, maxFlows, flowType, flowName, matchType, archyYamlDirectory, includeQueueMemberCounts, priorityReviewThreshold }),
    summary: {
      flowsWithQueues: audits.filter((a) => a.components?.queues?.length).length,
      flowsWithSkills: audits.filter((a) => a.components?.skills?.length).length,
      flowsWithPriority: audits.filter((a) => a.components?.priorities?.length).length,
      flowsWithYaml: audits.filter((a) => a.sources?.yamlScanned).length
    },
    findingSummary: findingSummary(sorted),
    findings: sorted,
    flows: audits.map((a) => ({ flow: a.flow, sources: a.sources, componentCounts: {
      queues: a.components?.queues?.length || 0,
      skills: a.components?.skills?.length || 0,
      priorities: a.components?.priorities?.length || 0,
      routingLines: a.components?.routingLines?.length || 0
    }, findings: a.findings }))
  };
}


/** =========================
 * V1.6.0 - OBJECT LIFECYCLE + DATA COLLECTION ENGINE
 * ========================= */
const V160_OBJECT_TYPES = {
  users: {
    label: "Users",
    path: "/api/v2/users",
    detailPath: (id) => `/api/v2/users/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "email", "state", "division", "createdDate", "modifiedDate"]
  },
  queues: {
    label: "Queues",
    path: "/api/v2/routing/queues",
    detailPath: (id) => `/api/v2/routing/queues/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "division", "memberCount", "createdDate", "modifiedDate", "description"]
  },
  groups: {
    label: "Groups",
    path: "/api/v2/groups",
    detailPath: (id) => `/api/v2/groups/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "type", "visibility", "createdDate", "modifiedDate", "description"]
  },
  roles: {
    label: "Roles",
    path: "/api/v2/authorization/roles",
    detailPath: (id) => `/api/v2/authorization/roles/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "createdDate", "modifiedDate", "description"]
  },
  divisions: {
    label: "Divisions",
    path: "/api/v2/authorization/divisions",
    detailPath: (id) => `/api/v2/authorization/divisions/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "createdDate", "modifiedDate", "description"]
  },
  skills: {
    label: "Routing Skills",
    path: "/api/v2/routing/skills",
    detailPath: (id) => `/api/v2/routing/skills/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "createdDate", "modifiedDate"]
  },
  languageSkills: {
    label: "Language Skills",
    path: "/api/v2/routing/languages",
    detailPath: (id) => `/api/v2/routing/languages/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "createdDate", "modifiedDate"]
  },
  wrapupCodes: {
    label: "Wrap-up Codes",
    path: "/api/v2/routing/wrapupcodes",
    detailPath: (id) => `/api/v2/routing/wrapupcodes/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "division", "createdDate", "modifiedDate"]
  },
  flows: {
    label: "Architect Flows",
    path: "/api/v2/flows",
    detailPath: (id) => `/api/v2/flows/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "type", "division", "publishedVersion", "createdDate", "modifiedDate", "description"]
  },
  prompts: {
    label: "Architect Prompts",
    path: "/api/v2/architect/prompts",
    detailPath: (id) => `/api/v2/architect/prompts/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "createdDate", "modifiedDate", "description"]
  },
  dataTables: {
    label: "Architect Data Tables",
    path: "/api/v2/flows/datatables",
    detailPath: (id) => `/api/v2/flows/datatables/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "division", "createdDate", "modifiedDate", "description"]
  },
  dataActions: {
    label: "Data Actions",
    path: "/api/v2/integrations/actions",
    detailPath: (id) => `/api/v2/integrations/actions/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "category", "integrationId", "createdDate", "modifiedDate"]
  },
  integrations: {
    label: "Integrations",
    path: "/api/v2/integrations",
    detailPath: (id) => `/api/v2/integrations/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "integrationType", "state", "createdDate", "modifiedDate"]
  },
  schedules: {
    label: "Schedules",
    path: "/api/v2/architect/schedules",
    detailPath: (id) => `/api/v2/architect/schedules/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "division", "createdDate", "modifiedDate", "description"]
  },
  scheduleGroups: {
    label: "Schedule Groups",
    path: "/api/v2/architect/schedulegroups",
    detailPath: (id) => `/api/v2/architect/schedulegroups/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "division", "createdDate", "modifiedDate", "description"]
  },
  ivrs: {
    label: "IVRs",
    path: "/api/v2/architect/ivrs",
    detailPath: (id) => `/api/v2/architect/ivrs/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "division", "dnis", "createdDate", "modifiedDate"]
  },
  oauthClients: {
    label: "OAuth Clients",
    path: "/api/v2/oauth/clients",
    detailPath: (id) => `/api/v2/oauth/clients/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "authorizedGrantType", "state", "createdDate", "modifiedDate"]
  },
  locations: {
    label: "Locations",
    path: "/api/v2/locations",
    detailPath: (id) => `/api/v2/locations/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "createdDate", "modifiedDate", "address"]
  },
  sites: {
    label: "Sites",
    path: "/api/v2/telephony/providers/edges/sites",
    detailPath: (id) => `/api/v2/telephony/providers/edges/sites/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "createdDate", "modifiedDate", "description"]
  },
  trunks: {
    label: "Trunks",
    path: "/api/v2/telephony/providers/edges/trunks",
    detailPath: (id) => `/api/v2/telephony/providers/edges/trunks/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "trunkType", "createdDate", "modifiedDate", "description"]
  },
  scripts: {
    label: "Scripts",
    path: "/api/v2/scripts",
    detailPath: (id) => `/api/v2/scripts/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "createdDate", "modifiedDate", "description"]
  },
  recordingPolicies: {
    label: "Recording Policies",
    path: "/api/v2/recording/policies",
    detailPath: (id) => `/api/v2/recording/policies/${encodeURIComponent(id)}`,
    defaultFields: ["objectType", "id", "name", "enabled", "createdDate", "modifiedDate", "description"]
  }
};

const V160_DEFAULT_OBJECT_TYPES = [
  "users", "queues", "roles", "groups", "divisions", "skills", "languageSkills", "wrapupCodes", "flows",
  "prompts", "dataTables", "dataActions", "integrations", "schedules", "scheduleGroups", "ivrs", "oauthClients"
];

const V160_FLOW_COMPONENT_OBJECT_TYPES = ["queues", "skills", "languageSkills", "schedules", "scheduleGroups", "dataTables", "dataActions", "prompts", "wrapupCodes"];

function resolveV160ObjectType(type) {
  const raw = String(type || "").trim();
  const canonical = Object.keys(V160_OBJECT_TYPES).find((k) => norm(k) === norm(raw) || norm(V160_OBJECT_TYPES[k].label) === norm(raw));
  if (!canonical) throw new Error(`Unknown object type '${type}'. Use gc_object_catalog for supported object types.`);
  return canonical;
}

function firstDateValue(obj, names) {
  for (const n of names) {
    const v = getByPath(obj, n);
    if (v) return v;
  }
  return "";
}

function normalizeObjectInventoryRow(objectType, obj, extra = {}) {
  const createdDate = firstDateValue(obj, ["createdDate", "dateCreated", "created", "createdAt", "version.createdDate"]);
  const modifiedDate = firstDateValue(obj, ["modifiedDate", "dateModified", "modified", "updatedDate", "updatedAt", "version.modifiedDate"]);
  const division = obj?.division?.name || obj?.division?.id || obj?.division || "";
  return compactObject({
    objectType,
    label: V160_OBJECT_TYPES[objectType]?.label,
    id: obj?.id,
    name: obj?.name || obj?.displayName || obj?.username || obj?.email,
    description: obj?.description,
    state: obj?.state || obj?.status || obj?.enabled,
    division,
    createdDate,
    modifiedDate,
    createdBy: obj?.createdBy?.name || obj?.createdBy?.id || obj?.createdBy,
    modifiedBy: obj?.modifiedBy?.name || obj?.modifiedBy?.id || obj?.modifiedBy,
    type: obj?.type || obj?.flowType || obj?.integrationType || obj?.authorizedGrantType,
    memberCount: obj?.memberCount,
    publishedVersion: obj?.publishedVersion?.version || obj?.publishedVersion,
    checkedInVersion: obj?.checkedInVersion?.version || obj?.checkedInVersion,
    savedVersion: obj?.savedVersion?.version || obj?.savedVersion,
    ...extra
  });
}

async function fetchV160Objects(token, objectType, { pageSize = 100, maxPages = 10, includeDetails = false } = {}) {
  const t = resolveV160ObjectType(objectType);
  const cfg = V160_OBJECT_TYPES[t];
  const ps = Math.min(500, Math.max(1, Number(pageSize) || 100));
  const mp = Math.max(1, Number(maxPages) || 10);
  let entities = [];
  try {
    entities = await fetchAllPages(token, cfg.path, ps, mp);
    if (includeDetails && cfg.detailPath) {
      entities = await mapLimit(entities, Math.min(4, Math.max(1, Number(API_CONCURRENCY_LIMIT) || 4)), async (x) => {
        if (!x?.id) return x;
        try { return await gcGet(cfg.detailPath(x.id), token); } catch { return x; }
      });
    }
    return { ok: true, objectType: t, count: entities.length, entities };
  } catch (e) {
    return { ok: false, objectType: t, count: 0, entities: [], error: String(e?.message || e), endpoint: cfg.path };
  }
}

function objectFieldsForTypes(types) {
  const s = new Set(["objectType", "id", "name", "division", "createdDate", "modifiedDate", "state", "description"]);
  for (const t of safeArray(types)) {
    const cfg = V160_OBJECT_TYPES[t];
    for (const f of safeArray(cfg?.defaultFields)) s.add(f);
  }
  return Array.from(s);
}

function filterObjectFields(rows, fields) {
  if (!Array.isArray(fields) || !fields.length) return rows;
  return rows.map((row) => {
    const out = {};
    for (const f of fields) out[f] = row[f] ?? getByPath(row, f);
    return out;
  });
}

function daysSinceDate(value) {
  if (!value) return null;
  const t = Date.parse(value);
  if (!Number.isFinite(t)) return null;
  return Math.floor((Date.now() - t) / 86400000);
}

function compactNameList(items, max = 50) {
  return safeArray(items).map((x) => x?.name || x?.id || x).filter(Boolean).slice(0, max);
}

async function fetchFlowDependencyInventory(token, { pageSize = 200, maxPages = 100 } = {}) {
  const out = {};
  const errors = {};
  for (const t of V160_FLOW_COMPONENT_OBJECT_TYPES) {
    const res = await fetchV160Objects(token, t, { pageSize, maxPages, includeDetails: false });
    out[t] = res.entities || [];
    if (!res.ok) errors[t] = res.error;
  }
  return { resources: out, errors };
}

function componentTypeLabel(objectType) {
  return {
    queues: "Queues",
    skills: "Skills",
    languageSkills: "Language Skills",
    schedules: "Schedules",
    scheduleGroups: "Schedule Groups",
    dataTables: "Data Tables",
    dataActions: "Data Actions",
    prompts: "Prompts",
    wrapupCodes: "Wrap-up Codes"
  }[objectType] || titleize(objectType);
}

function collectComponentMatchesFromText(text, resourcesByType, maxMatchesPerType = 500) {
  const matchesByType = {};
  const sourceText = String(text || "");
  for (const [objectType, resources] of Object.entries(resourcesByType || {})) {
    const found = matchNamedResourcesInText(sourceText, safeArray(resources), objectType, maxMatchesPerType).map((m) => {
      const obj = m.id ? safeArray(resources).find((x) => norm(x.id) === norm(m.id)) : safeArray(resources).find((x) => norm(x.name) === norm(m.name));
      return compactObject({
        componentType: componentTypeLabel(objectType),
        objectType,
        id: obj?.id || m.id,
        name: obj?.name || m.name,
        matchType: m.matchType,
        division: obj?.division?.name || obj?.division?.id,
        createdDate: firstDateValue(obj || {}, ["createdDate", "dateCreated", "created", "createdAt"]),
        modifiedDate: firstDateValue(obj || {}, ["modifiedDate", "dateModified", "modified", "updatedAt"])
      });
    });
    const seen = new Set();
    matchesByType[objectType] = found.filter((m) => {
      const key = `${m.objectType}|${m.id || ""}|${norm(m.name)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  return matchesByType;
}

function extractStaticComponentLinesFromYaml(yamlText) {
  const lines = String(yamlText || "").split(/\r?\n/);
  const out = {
    dataTableLines: [],
    dataActionLines: [],
    scheduleLines: [],
    promptLines: [],
    wrapupLines: [],
    menuLines: [],
    dtmfLines: [],
    invalidInputLines: [],
    noInputLines: []
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const item = { lineNumber: i + 1, line };
    if (/data\s*table|datatable/i.test(line)) out.dataTableLines.push(item);
    if (/data\s*action|dataaction|integration\s*action/i.test(line)) out.dataActionLines.push(item);
    if (/schedule\s*group|schedulegroup/i.test(line)) out.scheduleLines.push(item);
    else if (/\bschedule\b/i.test(line)) out.scheduleLines.push(item);
    if (/\bprompt\b|audio|tts/i.test(line)) out.promptLines.push(item);
    if (/wrapup|wrap-up/i.test(line)) out.wrapupLines.push(item);
    if (/\bmenu\b|reusable\s*menu/i.test(line)) out.menuLines.push(item);
    if (/dtmf|digit|keypress|key\s*press|input/i.test(line)) out.dtmfLines.push(item);
    if (/invalid\s*input|invalid\s*choice|no\s*match/i.test(line)) out.invalidInputLines.push(item);
    if (/no\s*input|timeout|no\s*entry/i.test(line)) out.noInputLines.push(item);
  }
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.slice(0, 100)]));
}

async function collectOneFlowComponents(token, flow, { yamlText = "", yamlSource, includeQueueMemberCounts = false, priorityReviewThreshold = 500, dependencyInventory = null } = {}) {
  const detail = flow?.id ? await gcGet(`/api/v2/flows/${encodeURIComponent(flow.id)}`, token).catch(() => flow) : flow;
  const routingAudit = await auditFlowComponentsFromSources(token, {
    flow: detail,
    flowDetail: detail,
    yamlText,
    yamlSource,
    includeQueueMemberCounts,
    priorityReviewThreshold
  });
  const deps = dependencyInventory || await fetchFlowDependencyInventory(token);
  const sourceText = [JSON.stringify(detail || {}), yamlText || "", safeArray(routingAudit.components?.routingLines).map((x) => x.context || x.line).join("\n")].join("\n");
  const componentMatches = collectComponentMatchesFromText(sourceText, deps.resources || {});
  const staticLines = extractStaticComponentLinesFromYaml(yamlText || "");
  const queues = safeArray(routingAudit.components?.queues);
  const skills = safeArray(routingAudit.components?.skills);
  return {
    flow: summarizeFlow(detail || flow || {}),
    source: compactObject({ yamlScanned: Boolean(yamlText), yamlSource }),
    components: {
      queues,
      skills,
      languageSkills: safeArray(componentMatches.languageSkills),
      schedules: safeArray(componentMatches.schedules),
      scheduleGroups: safeArray(componentMatches.scheduleGroups),
      dataTables: safeArray(componentMatches.dataTables),
      dataActions: safeArray(componentMatches.dataActions),
      prompts: safeArray(componentMatches.prompts),
      wrapupCodes: safeArray(componentMatches.wrapupCodes),
      priorities: safeArray(routingAudit.components?.priorities),
      preferredAgentLines: safeArray(routingAudit.components?.preferredAgentLines),
      routingLines: safeArray(routingAudit.components?.routingLines),
      ...staticLines
    },
    componentCounts: {
      queues: queues.length,
      skills: skills.length,
      languageSkills: safeArray(componentMatches.languageSkills).length,
      schedules: safeArray(componentMatches.schedules).length,
      scheduleGroups: safeArray(componentMatches.scheduleGroups).length,
      dataTables: safeArray(componentMatches.dataTables).length,
      dataActions: safeArray(componentMatches.dataActions).length,
      prompts: safeArray(componentMatches.prompts).length,
      wrapupCodes: safeArray(componentMatches.wrapupCodes).length,
      priorities: safeArray(routingAudit.components?.priorities).length
    },
    findings: safeArray(routingAudit.findings),
    dependencyInventoryErrors: deps.errors && Object.keys(deps.errors).length ? deps.errors : undefined
  };
}

function flowComponentsToRow(item) {
  const c = item.components || {};
  return {
    flowId: item.flow?.id || "",
    flowName: item.flow?.name || "",
    flowType: item.flow?.type || "",
    division: item.flow?.division || "",
    publishedVersion: item.flow?.publishedVersion || "",
    checkedInVersion: item.flow?.checkedInVersion || "",
    createdDate: item.flow?.createdDate || "",
    modifiedDate: item.flow?.modifiedDate || "",
    queues: compactNameList(c.queues, 200).join("; "),
    skills: compactNameList(c.skills, 200).join("; "),
    languageSkills: compactNameList(c.languageSkills, 200).join("; "),
    schedules: compactNameList(c.schedules, 200).join("; "),
    scheduleGroups: compactNameList(c.scheduleGroups, 200).join("; "),
    dataTables: compactNameList(c.dataTables, 200).join("; "),
    dataActions: compactNameList(c.dataActions, 200).join("; "),
    prompts: compactNameList(c.prompts, 200).join("; "),
    wrapupCodes: compactNameList(c.wrapupCodes, 200).join("; "),
    priorities: safeArray(c.priorities).map((p) => p.value ?? p.line ?? "").filter(Boolean).join("; "),
    transferTargets: safeArray(c.routingLines).map((x) => x.line || x.context).filter(Boolean).slice(0, 20).join(" | "),
    findings: safeArray(item.findings).map((f) => `[${f.severity}] ${f.title}`).join("; ")
  };
}

function componentMatrixFromFlowComponents(flowComponents) {
  const byKey = new Map();
  for (const item of safeArray(flowComponents)) {
    const flowName = item.flow?.name || item.flow?.id || "Unknown flow";
    for (const [objectType, values] of Object.entries(item.components || {})) {
      if (!Array.isArray(values)) continue;
      if (![...V160_FLOW_COMPONENT_OBJECT_TYPES, "priorities"].includes(objectType)) continue;
      for (const v of values) {
        const name = v?.name || v?.id || v?.value || v?.line || "(detected reference)";
        const id = v?.id || "";
        const key = `${objectType}|${id}|${name}`;
        if (!byKey.has(key)) byKey.set(key, { componentType: componentTypeLabel(objectType), objectType, id, name, usedByFlows: new Set(), count: 0 });
        const row = byKey.get(key);
        row.usedByFlows.add(flowName);
        row.count += 1;
      }
    }
  }
  return Array.from(byKey.values()).map((x) => ({
    componentType: x.componentType,
    objectType: x.objectType,
    id: x.id,
    name: x.name,
    flowCount: x.usedByFlows.size,
    usedByFlows: Array.from(x.usedByFlows).sort().join("; "),
    referenceCount: x.count
  })).sort((a, b) => String(a.componentType).localeCompare(String(b.componentType)) || String(a.name).localeCompare(String(b.name)));
}

async function runObjectInventory({ objectTypes = V160_DEFAULT_OBJECT_TYPES, pageSize = 100, maxPages = 5, includeDetails = false, fields, includeErrors = true } = {}) {
  const token = await getAccessToken();
  const types = safeArray(objectTypes).length ? safeArray(objectTypes).map(resolveV160ObjectType) : V160_DEFAULT_OBJECT_TYPES;
  const results = [];
  const errors = {};
  for (const t of types) {
    const res = await fetchV160Objects(token, t, { pageSize, maxPages, includeDetails });
    if (!res.ok) {
      errors[t] = res.error;
      continue;
    }
    for (const obj of res.entities) results.push(normalizeObjectInventoryRow(t, obj));
  }
  const selectedFields = Array.isArray(fields) && fields.length ? fields : objectFieldsForTypes(types);
  return {
    generatedAt: new Date().toISOString(),
    objectTypes: types,
    count: results.length,
    fields: selectedFields,
    rows: filterObjectFields(results, selectedFields),
    errors: includeErrors && Object.keys(errors).length ? errors : undefined
  };
}

export function gcObjectCatalogTool() {
  return {
    version: "1.6.0",
    objectTypes: Object.fromEntries(Object.entries(V160_OBJECT_TYPES).map(([key, cfg]) => [key, {
      label: cfg.label,
      endpoint: cfg.path,
      defaultFields: cfg.defaultFields,
      supportsDetail: Boolean(cfg.detailPath)
    }])),
    dataCollectionTools: ["gc_object_inventory", "gc_collect_all_objects", "gc_collect_flow_components", "gc_collect_flow_component_matrix", "gc_export_object_inventory_csv", "gc_export_object_inventory_markdown", "gc_export_flow_components_csv"],
    auditTools: ["gc_audit_all_objects", "gc_audit_object_lifecycle", "gc_audit_stale_objects", "gc_audit_orphaned_objects", "gc_audit_recent_admin_activity", "gc_object_change_history"]
  };
}

export async function gcObjectInventoryTool(args = {}) {
  return runObjectInventory(args);
}

export async function gcCollectAllObjectsTool(args = {}) {
  return runObjectInventory({ ...args, objectTypes: args?.objectTypes || V160_DEFAULT_OBJECT_TYPES });
}

export async function gcObjectDetailTool({ objectType, objectId, objectName, matchType = "CONTAINS", includeRaw = true } = {}) {
  const t = resolveV160ObjectType(objectType);
  if (!objectId && !objectName) throw new Error("Provide objectId or objectName.");
  const token = await getAccessToken();
  const cfg = V160_OBJECT_TYPES[t];
  let obj = null;
  let candidates = [];
  if (objectId) {
    obj = cfg.detailPath ? await gcGet(cfg.detailPath(objectId), token) : null;
  } else {
    const res = await fetchV160Objects(token, t, { pageSize: 100, maxPages: 50, includeDetails: false });
    candidates = safeArray(res.entities).filter((x) => matches(x?.name || x?.displayName || x?.username || x?.email, objectName, matchType));
    if (!candidates.length) throw new Error(`No ${t} object found matching '${objectName}'.`);
    obj = candidates.sort((a, b) => String(a.name || "").length - String(b.name || "").length)[0];
    if (cfg.detailPath && obj?.id) obj = await gcGet(cfg.detailPath(obj.id), token).catch(() => obj);
  }
  return {
    objectType: t,
    summary: normalizeObjectInventoryRow(t, obj),
    candidates: candidates.length > 1 ? candidates.map((x) => normalizeObjectInventoryRow(t, x)).slice(0, 25) : undefined,
    raw: includeRaw ? obj : undefined
  };
}

export async function gcCollectFlowComponentsTool({
  flowId,
  flowName,
  flowType,
  matchType = "CONTAINS",
  pageSize = 100,
  maxPages = 5,
  maxFlows = 25,
  archyYamlDirectory,
  yamlText,
  archyYamlPath,
  includeQueueMemberCounts = false,
  priorityReviewThreshold = 500,
  includeMatrix = false
} = {}) {
  const token = await getAccessToken();
  let flows = [];
  if (flowId || flowName) {
    const resolved = await resolveFlow(token, { flowId, flowName, matchType });
    flows = [resolved.flow];
  } else {
    flows = (await fetchFlows(token, { pageSize, maxPages, flowType, matchType })).slice(0, Math.max(1, Number(maxFlows) || 25));
  }
  const dependencyInventory = await fetchFlowDependencyInventory(token);
  const rows = [];
  for (const f of flows) {
    let localYaml = "";
    let source = null;
    if (flows.length === 1 && (yamlText || archyYamlPath)) {
      const y = tryReadYamlInput({ yamlText, archyYamlPath });
      if (y.error) throw new Error(y.error);
      localYaml = y.text;
      source = y.filePath || y.source;
    } else if (archyYamlDirectory) {
      const path = findYamlForFlow(f, archyYamlDirectory);
      if (path) {
        const y = tryReadYamlInput({ archyYamlPath: path });
        localYaml = y.text;
        source = y.filePath || y.source;
      }
    }
    rows.push(await collectOneFlowComponents(token, f, { yamlText: localYaml, yamlSource: source, includeQueueMemberCounts, priorityReviewThreshold, dependencyInventory }));
  }
  const flatRows = rows.map(flowComponentsToRow);
  return {
    generatedAt: new Date().toISOString(),
    count: rows.length,
    filters: compactObject({ flowId, flowName, flowType, matchType, pageSize, maxPages, maxFlows, archyYamlDirectory, includeQueueMemberCounts, priorityReviewThreshold }),
    rows: flatRows,
    flows: rows,
    matrix: includeMatrix ? componentMatrixFromFlowComponents(rows) : undefined
  };
}

export async function gcCollectFlowComponentMatrixTool(args = {}) {
  const result = await gcCollectFlowComponentsTool({ ...args, includeMatrix: true });
  return {
    generatedAt: result.generatedAt,
    count: result.matrix?.length || 0,
    filters: result.filters,
    matrix: result.matrix || [],
    flowCount: result.count
  };
}

export async function gcExportFlowComponentsCsvTool(args = {}) {
  const result = await gcCollectFlowComponentsTool(args || {});
  const fields = ["flowId", "flowName", "flowType", "division", "publishedVersion", "checkedInVersion", "createdDate", "modifiedDate", "queues", "skills", "languageSkills", "schedules", "scheduleGroups", "dataTables", "dataActions", "prompts", "wrapupCodes", "priorities", "transferTargets", "findings"];
  const parser = new Json2csvParser({ fields });
  return parser.parse(result.rows || []);
}

export async function gcAuditFlowComponentsTool(args = {}) {
  const result = await gcCollectFlowComponentsTool(args || {});
  const findings = sortFindings(safeArray(result.flows).flatMap((f) => safeArray(f.findings)));
  return {
    generatedAt: new Date().toISOString(),
    scannedFlows: result.count,
    findingSummary: findingSummary(findings),
    findings,
    flowRows: result.rows
  };
}

export async function gcObjectRelationshipsTool({ objectType, objectId, objectName, matchType = "CONTAINS", archyYamlDirectory, maxFlows = 100 } = {}) {
  const detail = await gcObjectDetailTool({ objectType, objectId, objectName, matchType, includeRaw: false });
  const target = detail.summary;
  const t = detail.objectType;
  const token = await getAccessToken();
  const relationships = [];
  if (["queues", "skills", "languageSkills", "schedules", "scheduleGroups", "dataTables", "dataActions", "prompts", "wrapupCodes"].includes(t)) {
    const flows = (await fetchFlows(token, { pageSize: 100, maxPages: 20 })).slice(0, Math.max(1, Number(maxFlows) || 100));
    for (const f of flows) {
      let yaml = "";
      let yamlSource = null;
      if (archyYamlDirectory) {
        const path = findYamlForFlow(f, archyYamlDirectory);
        if (path) { const y = tryReadYamlInput({ archyYamlPath: path }); yaml = y.text; yamlSource = y.filePath || y.source; }
      }
      const flowDetail = await gcGet(`/api/v2/flows/${encodeURIComponent(f.id)}`, token).catch(() => f);
      const text = [JSON.stringify(flowDetail || {}), yaml].join("\n");
      const hitById = target.id && norm(text).includes(norm(target.id));
      const hitByName = target.name && norm(text).includes(norm(target.name));
      if (hitById || hitByName) {
        relationships.push(compactObject({ relationship: "usedByFlow", objectType: "flows", id: f.id, name: f.name, flowType: f.type, matchType: hitById ? "id" : "name", yamlSource }));
      }
    }
  }
  if (t === "queues" && target.id) {
    const members = await gcGet(`/api/v2/routing/queues/${encodeURIComponent(target.id)}/members?pageSize=100&pageNumber=1`, token).catch((e) => ({ error: String(e?.message || e), entities: [] }));
    relationships.push({ relationship: "hasMembers", objectType: "users", count: members.total ?? safeArray(members.entities).length, samples: safeArray(members.entities).slice(0, 20).map((m) => ({ id: m.id, name: m.name, username: m.username })) });
  }
  return { generatedAt: new Date().toISOString(), target, relationships, relationshipCount: relationships.length };
}

function makeAuditQueryBody({ interval, startDate, endDate, days = 7, serviceName = "ContactCenter", entityId, entityType, userId, action, pageSize = 100, pageNumber = 1 } = {}) {
  const queryInterval = normalizeInterval({ interval, startDate, endDate, days });
  const [from, to] = String(queryInterval).split("/");
  const filters = [];
  if (entityId) filters.push({ property: "entity.id", value: String(entityId) });
  if (entityType) filters.push({ property: "entity.type", value: String(entityType) });
  if (userId) filters.push({ property: "user.id", value: String(userId) });
  if (action) filters.push({ property: "action", value: String(action) });
  return compactObject({ serviceName, startDate: from, endDate: to, filters, pageSize, pageNumber });
}

async function queryAuditsBestEffort(token, args = {}) {
  const body = args.rawQuery && typeof args.rawQuery === "object" ? args.rawQuery : makeAuditQueryBody(args);
  const useRealtime = args.useRealtime !== false;
  const paths = useRealtime ? ["/api/v2/audits/query/realtime", "/api/v2/audits/query"] : ["/api/v2/audits/query", "/api/v2/audits/query/realtime"];
  const errors = [];
  for (const path of paths) {
    try {
      const res = await gcPost(path, token, body);
      if (path.endsWith("/query") && (res?.id || res?.transactionId)) {
        const id = res.id || res.transactionId;
        let status = res;
        for (let i = 0; i < 20; i++) {
          await sleep(Math.min(5000, 500 + i * 250));
          status = await gcGet(`/api/v2/audits/query/${encodeURIComponent(id)}`, token).catch(() => status);
          const state = String(status?.state || status?.status || "").toLowerCase();
          if (["complete", "completed", "fulfilled", "succeeded", "success"].includes(state)) break;
        }
        const results = await gcGet(`/api/v2/audits/query/${encodeURIComponent(id)}/results`, token).catch((e) => ({ error: String(e?.message || e) }));
        return { ok: true, endpoint: path, query: body, transactionId: id, status, results };
      }
      return { ok: true, endpoint: path, query: body, results: res };
    } catch (e) {
      errors.push({ endpoint: path, error: String(e?.message || e) });
    }
  }
  return { ok: false, query: body, errors, hint: "Audit APIs require audits:audit:view and audit service/topic availability. Realtime audit events are commonly limited to recent events." };
}

export async function gcObjectChangeHistoryTool({ objectType, objectId, objectName, matchType = "CONTAINS", interval, startDate, endDate, days = 14, serviceName = "ContactCenter", entityType, useRealtime = true, pageSize = 100, pageNumber = 1, rawQuery } = {}) {
  const token = await getAccessToken();
  let target = null;
  let entityId = objectId;
  if ((objectType && objectName) || (objectType && objectId)) {
    const detail = await gcObjectDetailTool({ objectType, objectId, objectName, matchType, includeRaw: false }).catch(() => null);
    target = detail?.summary || null;
    entityId = entityId || target?.id;
  }
  const audit = await queryAuditsBestEffort(token, { rawQuery, interval, startDate, endDate, days, serviceName, entityId, entityType: entityType || objectType, useRealtime, pageSize, pageNumber });
  return { generatedAt: new Date().toISOString(), target, audit };
}

export async function gcAuditRecentAdminActivityTool({ interval, startDate, endDate, days = 7, serviceName = "ContactCenter", useRealtime = true, pageSize = 100, pageNumber = 1, rawQuery } = {}) {
  const token = await getAccessToken();
  const audit = await queryAuditsBestEffort(token, { rawQuery, interval, startDate, endDate, days, serviceName, useRealtime, pageSize, pageNumber });
  return { generatedAt: new Date().toISOString(), audit };
}

export async function gcAuditStaleObjectsTool({ objectTypes = V160_DEFAULT_OBJECT_TYPES, staleDays = 365, pageSize = 100, maxPages = 10, limitFindings = 500 } = {}) {
  const inv = await runObjectInventory({ objectTypes, pageSize, maxPages, includeDetails: false });
  const threshold = Math.max(1, Number(staleDays) || 365);
  const findings = [];
  for (const row of safeArray(inv.rows)) {
    const age = daysSinceDate(row.modifiedDate || row.createdDate);
    if (age != null && age >= threshold) {
      pushFinding(findings, "low", "Object Lifecycle", "Stale object", `${row.objectType} '${row.name || row.id}' has not been modified for approximately ${age} days.`, "Review whether this object is still required, still documented, and still used by flows/routing/configuration.", { objectType: row.objectType, objectId: row.id, objectName: row.name, ageDays: age, modifiedDate: row.modifiedDate });
    }
  }
  const sorted = sortFindings(findings).slice(0, Math.max(1, Number(limitFindings) || 500));
  return { generatedAt: new Date().toISOString(), scannedObjects: inv.count, staleDays: threshold, findingSummary: findingSummary(sorted), findings: sorted, errors: inv.errors };
}

export async function gcAuditObjectLifecycleTool({ objectTypes = V160_DEFAULT_OBJECT_TYPES, pageSize = 100, maxPages = 10, staleDays = 365, missingDescription = true, missingDivision = true, limitFindings = 500 } = {}) {
  const inv = await runObjectInventory({ objectTypes, pageSize, maxPages, includeDetails: false });
  const findings = [];
  for (const row of safeArray(inv.rows)) {
    const age = daysSinceDate(row.modifiedDate || row.createdDate);
    if (age != null && age >= Math.max(1, Number(staleDays) || 365)) {
      pushFinding(findings, "low", "Object Lifecycle", "Stale object", `${row.objectType} '${row.name || row.id}' has not been modified for approximately ${age} days.`, "Validate if the object is still required or can be archived/removed after change review.", { objectType: row.objectType, objectId: row.id, objectName: row.name, ageDays: age });
    }
    if (missingDescription && ["queues", "flows", "groups", "roles", "dataActions", "dataTables", "schedules", "scheduleGroups"].includes(row.objectType) && !row.description) {
      pushFinding(findings, "info", "Object Lifecycle", "Missing description", `${row.objectType} '${row.name || row.id}' has no description in the returned inventory.`, "Add a meaningful description to support handover, audit evidence, and future maintenance.", { objectType: row.objectType, objectId: row.id, objectName: row.name });
    }
    if (missingDivision && ["queues", "flows", "wrapupCodes", "schedules", "scheduleGroups", "dataTables"].includes(row.objectType) && !row.division) {
      pushFinding(findings, "medium", "Object Lifecycle", "Missing or unavailable division", `${row.objectType} '${row.name || row.id}' did not return a division value.`, "Validate division assignment and OAuth client division access.", { objectType: row.objectType, objectId: row.id, objectName: row.name });
    }
  }
  const sorted = sortFindings(findings).slice(0, Math.max(1, Number(limitFindings) || 500));
  return { generatedAt: new Date().toISOString(), scannedObjects: inv.count, findingSummary: findingSummary(sorted), findings: sorted, errors: inv.errors };
}

export async function gcAuditOrphanedObjectsTool({ archyYamlDirectory, pageSize = 100, maxPages = 10, maxFlows = 100, limitFindings = 500 } = {}) {
  const token = await getAccessToken();
  const flowComponents = await gcCollectFlowComponentsTool({ pageSize, maxPages, maxFlows, archyYamlDirectory, includeMatrix: true });
  const matrix = safeArray(flowComponents.matrix);
  const usedByKey = new Set(matrix.map((m) => `${m.objectType}|${m.id || ""}|${norm(m.name)}`));
  const deps = await fetchFlowDependencyInventory(token, { pageSize, maxPages });
  const findings = [];
  for (const t of V160_FLOW_COMPONENT_OBJECT_TYPES) {
    for (const obj of safeArray(deps.resources?.[t])) {
      const key = `${t}|${obj.id || ""}|${norm(obj.name)}`;
      const nameKey = `${t}||${norm(obj.name)}`;
      if (!usedByKey.has(key) && !usedByKey.has(nameKey)) {
        pushFinding(findings, "info", "Object Relationships", "Object not detected in scanned flows", `${componentTypeLabel(t)} '${obj.name || obj.id}' was not detected in the scanned Architect flow sources.`, "Confirm whether the object is used outside Architect flows before considering cleanup.", { objectType: t, objectId: obj.id, objectName: obj.name });
      }
    }
  }
  const sorted = sortFindings(findings).slice(0, Math.max(1, Number(limitFindings) || 500));
  return { generatedAt: new Date().toISOString(), scannedFlows: flowComponents.count, findingSummary: findingSummary(sorted), findings: sorted, dependencyInventoryErrors: deps.errors };
}

export async function gcAuditAllObjectsTool({ objectTypes = V160_DEFAULT_OBJECT_TYPES, pageSize = 100, maxPages = 5, staleDays = 365, includeFlowAudit = true, archyYamlDirectory, maxFlows = 50, limitFindings = 500 } = {}) {
  const [inventory, lifecycle] = await Promise.all([
    runObjectInventory({ objectTypes, pageSize, maxPages, includeDetails: false }),
    gcAuditObjectLifecycleTool({ objectTypes, pageSize, maxPages, staleDays, limitFindings })
  ]);
  let flowAudit = null;
  if (includeFlowAudit) {
    flowAudit = await gcAuditFlowComponentsTool({ pageSize, maxPages, maxFlows, archyYamlDirectory, limitFindings }).catch((e) => ({ error: String(e?.message || e) }));
  }
  const allFindings = sortFindings([...safeArray(lifecycle.findings), ...safeArray(flowAudit?.findings)]).slice(0, Math.max(1, Number(limitFindings) || 500));
  return {
    generatedAt: new Date().toISOString(),
    reportType: "Genesys Cloud Full Object Audit v1.6.0",
    inventorySummary: { objectCount: inventory.count, objectTypes: inventory.objectTypes, errors: inventory.errors },
    findingSummary: findingSummary(allFindings),
    findings: allFindings,
    sections: { lifecycle: lifecycle.findingSummary, flowComponents: flowAudit?.findingSummary || null },
    samples: { inventoryRows: safeArray(inventory.rows).slice(0, 50), flowRows: safeArray(flowAudit?.flowRows).slice(0, 25) }
  };
}

export async function gcExportObjectInventoryCsvTool(args = {}) {
  const inv = await runObjectInventory(args || {});
  const fields = Array.isArray(args?.fields) && args.fields.length ? args.fields : inv.fields;
  const parser = new Json2csvParser({ fields });
  return parser.parse(inv.rows || []);
}

export async function gcExportObjectInventoryMarkdownTool(args = {}) {
  const inv = await runObjectInventory(args || {});
  const lines = [];
  lines.push("# Genesys Cloud Object Inventory");
  lines.push("");
  lines.push(`Generated: ${inv.generatedAt}`);
  lines.push(`Object count: ${inv.count}`);
  lines.push("");
  const byType = {};
  for (const row of safeArray(inv.rows)) byType[row.objectType] = (byType[row.objectType] || 0) + 1;
  lines.push("## Summary by Object Type");
  lines.push("");
  for (const [type, count] of Object.entries(byType).sort()) lines.push(`- ${type}: ${count}`);
  if (inv.errors) {
    lines.push("");
    lines.push("## Collection Errors");
    lines.push("");
    for (const [type, error] of Object.entries(inv.errors)) lines.push(`- ${type}: ${error}`);
  }
  lines.push("");
  lines.push("## Inventory Rows");
  lines.push("");
  for (const row of safeArray(inv.rows).slice(0, 500)) {
    lines.push(`### ${row.objectType}: ${row.name || row.id}`);
    lines.push(`- ID: ${row.id || ""}`);
    if (row.division) lines.push(`- Division: ${row.division}`);
    if (row.state) lines.push(`- State: ${row.state}`);
    if (row.createdDate) lines.push(`- Created: ${row.createdDate}`);
    if (row.modifiedDate) lines.push(`- Modified: ${row.modifiedDate}`);
    if (row.description) lines.push(`- Description: ${row.description}`);
    lines.push("");
  }
  return lines.join("\n");
}


/** =========================
 * CHANNEL BLUEPRINT REPORTING LAYER (v1.7.0)
 * Produces template-aligned discovery evidence, draft observations, themes,
 * opportunities, and Markdown/Docx payload outputs. Read-only.
 * ========================= */
const BLUEPRINT_VERSION = "1.8.1";

const BLUEPRINT_SECTION_MAP = [
  {
    section: "1 Executive Summary",
    purpose: "Summarise key findings, challenges, opportunities, and assessment evidence.",
    mcpCoverage: "Partial / Strong draft support",
    primaryTools: ["gc_blueprint_evidence_pack", "gc_blueprint_metrics_pack", "gc_audit_report_summary", "gc_audit_all_objects", "gc_blueprint_discovery_summary"],
    evidenceNotes: "Final wording should combine platform evidence with workshops, interviews, call listening, and observations."
  },
  {
    section: "2 Member Journey Observations",
    purpose: "Capture entry complexity, authentication friction, transfer behaviour, escalation points, and self-service opportunities.",
    mcpCoverage: "Partial",
    primaryTools: ["gc_blueprint_member_journey_observations", "gc_blueprint_metrics_pack", "gc_conversation_timeline", "gc_disconnect_reason_audit", "gc_queue_conversation_audit", "gc_collect_flow_components"],
    evidenceNotes: "Authentication and member frustration usually require call listening, transcript, or workshop notes."
  },
  {
    section: "3 Agent & Team Leader Observations",
    purpose: "Capture manual intervention, knowledge dependency, queue management, escalation behaviour, and hold drivers.",
    mcpCoverage: "Partial",
    primaryTools: ["gc_blueprint_agent_team_leader_observations", "gc_blueprint_metrics_pack", "gc_audit_routing", "gc_queue_staffing", "gc_queue_conversation_audit", "gc_audit_recent_admin_activity"],
    evidenceNotes: "Manual workarounds and knowledge dependency are behavioural observations; MCP can support with queue, hold, routing, and change evidence."
  },
  {
    section: "4 Channel & Routing Observations",
    purpose: "Connect channel usage, queue design, routing behaviour, flows, skills, transfers, and specialist pathways.",
    mcpCoverage: "Strong",
    primaryTools: ["gc_blueprint_channel_routing_observations", "gc_blueprint_metrics_pack", "gc_blueprint_channel_statistics", "gc_collect_flow_components", "gc_collect_flow_component_matrix", "gc_audit_flows", "gc_audit_queues", "gc_query_queue_volumes"],
    evidenceNotes: "This is the strongest platform-data section for the MCP. Deep flow component evidence improves when Archy YAML is provided."
  },
  {
    section: "5 Platform Ownership & Governance Observations",
    purpose: "Capture ownership, change management, dependency risks, standards, and consistency.",
    mcpCoverage: "Partial / Strong technical evidence",
    primaryTools: ["gc_blueprint_governance_observations", "gc_audit_roles", "gc_role_impact", "gc_oauth_clients", "gc_audit_recent_admin_activity", "gc_object_change_history"],
    evidenceNotes: "MCP can show admin roles, OAuth clients, object lifecycle, stale objects, and change patterns; operating model ownership still needs stakeholder validation."
  },
  {
    section: "6 Emerging Themes",
    purpose: "Synthesize recurring patterns across discovery evidence.",
    mcpCoverage: "Draft support",
    primaryTools: ["gc_blueprint_emerging_themes", "gc_blueprint_evidence_pack"],
    evidenceNotes: "Themes should be cross-validated with qualitative discovery evidence before final report use."
  },
  {
    section: "7 Opportunity Summary",
    purpose: "Consolidate improvement opportunities for future design exploration.",
    mcpCoverage: "Strong candidate opportunity support",
    primaryTools: ["gc_blueprint_opportunity_summary", "gc_audit_report_summary", "gc_audit_all_objects", "gc_audit_flow_components"],
    evidenceNotes: "Outputs are framed as exploration areas, not final solution prescriptions."
  },
  {
    section: "8 Discovery Summary",
    purpose: "Create the concise senior-stakeholder summary and future design considerations.",
    mcpCoverage: "Draft support",
    primaryTools: ["gc_blueprint_discovery_summary", "gc_blueprint_export_markdown", "gc_blueprint_export_docx_payload"],
    evidenceNotes: "Final narrative should be reviewed by the assessor and tied to confirmed evidence sources."
  }
];

const BLUEPRINT_DISCOVERY_NOTE_FIELDS = [
  "workshops", "teamLeaderInterviews", "agentObservations", "journeyWalkthroughs", "callListeningSessions",
  "processReviews", "documentationReview", "otherNotes"
];

function textOrEmpty(v) {
  if (v == null) return "";
  if (typeof v === "string") return v;
  try { return JSON.stringify(v); } catch { return String(v); }
}

function safeSlice(arr, n = 10) {
  return safeArray(arr).slice(0, Math.max(0, Number(n) || 0));
}

function bulletList(values, max = 8) {
  return safeSlice(values, max).map((x) => `- ${textOrEmpty(x)}`).join("\n");
}

function priorityFromSeverity(sev) {
  const s = String(sev || "info").toLowerCase();
  if (["critical", "high"].includes(s)) return "High";
  if (s === "medium") return "Medium";
  return "Low";
}

function evidenceRefFromFinding(f) {
  const ev = f?.evidence || {};
  const bits = [];
  if (ev.objectType) bits.push(`Object type: ${ev.objectType}`);
  if (ev.objectName) bits.push(`Object: ${ev.objectName}`);
  if (ev.objectId) bits.push(`Object ID: ${ev.objectId}`);
  if (ev.queueName) bits.push(`Queue: ${ev.queueName}`);
  if (ev.queueId) bits.push(`Queue ID: ${ev.queueId}`);
  if (ev.flowName) bits.push(`Flow: ${ev.flowName}`);
  if (ev.flowId) bits.push(`Flow ID: ${ev.flowId}`);
  if (ev.userName) bits.push(`User: ${ev.userName}`);
  if (ev.userId) bits.push(`User ID: ${ev.userId}`);
  return bits.join("; ") || f?.area || "MCP audit evidence";
}

function findingToBlueprintFinding(f, idx = 0) {
  return {
    findingNumber: idx + 1,
    observation: `${f?.title || "Finding"}${f?.detail ? ` — ${f.detail}` : ""}`,
    evidenceSource: evidenceRefFromFinding(f),
    whyItMatters: f?.recommendation || "This should be reviewed during discovery synthesis because it may affect member experience, agent effort, reporting clarity, or platform sustainability.",
    priority: priorityFromSeverity(f?.severity),
    sourceFinding: f
  };
}

function selectFindingsByKeywords(findings, keywords, limit = 5) {
  const keys = safeArray(keywords).map((x) => String(x).toLowerCase());
  return safeArray(findings).filter((f) => {
    const txt = `${f?.area || ""} ${f?.title || ""} ${f?.detail || ""} ${f?.recommendation || ""}`.toLowerCase();
    return keys.some((k) => txt.includes(k));
  }).slice(0, limit);
}

function collectAllFindingsFromEvidence(evidencePack) {
  const ep = evidencePack || {};
  return [
    ...safeArray(ep.auditSummary?.topFindings),
    ...safeArray(ep.auditSummary?.findings),
    ...safeArray(ep.auditSummary?.detail?.users?.findings),
    ...safeArray(ep.auditSummary?.detail?.roles?.findings),
    ...safeArray(ep.auditSummary?.detail?.queues?.findings),
    ...safeArray(ep.objectAudit?.findings),
    ...safeArray(ep.flowComponents?.findings),
    ...safeArray(ep.conversationAudit?.findings)
  ];
}

function observationsFromFindings(title, findings, fallback, max = 5) {
  const selected = safeSlice(findings, max);
  if (!selected.length) {
    return [{ observation: fallback, evidence: "No MCP finding returned for this dimension in the selected scope.", evidenceStrength: "Requires discovery validation" }];
  }
  return selected.map((f) => ({
    observation: `${f.title || title}: ${f.detail || "Review required."}`,
    evidence: evidenceRefFromFinding(f),
    evidenceStrength: "Platform evidence",
    priority: priorityFromSeverity(f.severity),
    recommendedDiscoveryFollowUp: f.recommendation || "Validate with workshop, journey walkthrough, call listening, or observation evidence."
  }));
}

function inferBlueprintThemes(findings, { maxThemes = 5 } = {}) {
  const themes = [];
  const addTheme = (key, themeStatement, keywords, whyItMatters, potentialOpportunity) => {
    const ev = selectFindingsByKeywords(findings, keywords, 6);
    if (ev.length) themes.push({
      key,
      themeStatement,
      supportingEvidence: ev.map((f) => ({ observation: f.title, evidence: evidenceRefFromFinding(f), detail: f.detail })),
      whyItMatters,
      potentialOpportunity
    });
  };

  addTheme(
    "routing-complexity",
    "Routing and queue design may be creating complexity that requires review against member intent and operational ownership.",
    ["queue", "routing", "flow", "transfer", "skill", "priority", "acd"],
    "Routing complexity can increase transfer steps, administrative overhead, and reporting ambiguity.",
    "Explore queue rationalisation, flow simplification, and member-intent based routing design."
  );
  addTheme(
    "governance-standards",
    "Platform governance and standards may require strengthening to maintain a sustainable channel environment.",
    ["description", "stale", "lifecycle", "division", "oauth", "role", "permission", "admin", "change"],
    "Inconsistent standards and unclear ownership can make routine change slower and increase dependency risk.",
    "Define ownership, naming standards, decommissioning rules, and lightweight change governance."
  );
  addTheme(
    "access-risk",
    "User and role access patterns may need review to ensure least-privilege and operational alignment.",
    ["inactive", "role", "permission", "admin", "user", "access"],
    "Excessive or stale access increases support, governance, and compliance risk.",
    "Review elevated roles, inactive users, and access assignment standards."
  );
  addTheme(
    "flow-dependency-risk",
    "Architect flow dependencies may need documentation and validation to reduce change risk.",
    ["flow", "prompt", "data action", "data table", "schedule", "wrap", "unresolved"],
    "Undocumented flow dependencies can create fragility when queues, skills, schedules, data tables, prompts, or data actions change.",
    "Create flow component inventories and impact matrices before making routing or IVR changes."
  );
  addTheme(
    "conversation-friction",
    "Conversation analytics may indicate friction points that warrant journey review.",
    ["disconnect", "peer", "abandon", "wrap", "conversation", "wait", "hold", "transfer"],
    "Disconnect, transfer, wait, and wrap-up patterns can indicate journey friction, handoff issues, or operational workload drivers.",
    "Use call listening and transcripts to validate the behavioural drivers behind the analytics patterns."
  );

  if (!themes.length) {
    themes.push({
      key: "limited-evidence",
      themeStatement: "The selected scope did not return enough platform findings to identify strong recurring themes.",
      supportingEvidence: [],
      whyItMatters: "A small or new org may require more object creation, interaction history, workshop evidence, or a broader date range before themes can be confidently stated.",
      potentialOpportunity: "Use this MCP output as a baseline and rerun after more flows, queues, conversations, and discovery notes are available."
    });
  }
  return themes.slice(0, Math.max(1, Number(maxThemes) || 5));
}

function inferBlueprintOpportunities(findings, { maxOpportunities = 12 } = {}) {
  const opportunities = [];
  const addOpp = (area, keywords, summary, potentialBenefit) => {
    const ev = selectFindingsByKeywords(findings, keywords, 5);
    if (ev.length) opportunities.push({
      opportunityArea: area,
      summary,
      evidence: ev.map((f) => `${f.title}${f.detail ? ` — ${f.detail}` : ""}`).join(" | "),
      potentialBenefit,
      priority: ev.some((f) => ["critical", "high"].includes(String(f.severity).toLowerCase())) ? "H" : ev.some((f) => String(f.severity).toLowerCase() === "medium") ? "M" : "L"
    });
  };

  addOpp("Routing Simplification", ["queue", "routing", "transfer", "flow", "acd", "priority"], "Review routing and queue design against member intent and operational complexity.", "Reduced transfers, simpler journeys, clearer reporting, and lower support overhead.");
  addOpp("Queue Rationalisation", ["queue", "stale", "no members", "low volume", "orphan"], "Explore whether legacy, low-volume, or unstaffed queues should be consolidated, retired, or documented.", "Cleaner queue estate, reduced management effort, and improved reporting clarity.");
  addOpp("Governance Improvement", ["description", "division", "change", "oauth", "role", "permission", "admin", "lifecycle"], "Strengthen ownership, standards, and change controls around channel objects.", "Improved sustainability, reduced dependency risk, and safer routine change.");
  addOpp("Flow Dependency Management", ["flow", "data table", "data action", "schedule", "prompt", "wrap", "unresolved"], "Create and maintain flow component inventories and dependency impact views.", "Lower change risk and faster impact assessment for IVR/routing updates.");
  addOpp("Access Review", ["inactive", "role", "permission", "access", "user"], "Review user and role access for least privilege and current operational need.", "Reduced governance and security risk.");
  addOpp("Conversation Journey Review", ["disconnect", "abandon", "peer", "wait", "hold", "conversation", "wrap"], "Review conversation patterns and validate drivers through call listening and transcript review.", "Reduced friction, improved resolution experience, and better operational insight.");

  if (!opportunities.length) {
    opportunities.push({
      opportunityArea: "Evidence Development",
      summary: "Build more discovery evidence before prioritising design opportunities.",
      evidence: "The selected MCP scope returned limited findings.",
      potentialBenefit: "Improved confidence in the Channel Blueprint recommendations.",
      priority: "M"
    });
  }
  return opportunities.slice(0, Math.max(1, Number(maxOpportunities) || 12));
}

function normaliseDiscoveryNotes(discoveryNotes = {}) {
  const out = {};
  for (const f of BLUEPRINT_DISCOVERY_NOTE_FIELDS) out[f] = discoveryNotes?.[f] || "";
  if (typeof discoveryNotes === "string") out.otherNotes = discoveryNotes;
  return out;
}

function discoveryEvidenceSummary(discoveryNotes = {}) {
  const notes = normaliseDiscoveryNotes(discoveryNotes);
  const active = Object.entries(notes).filter(([, v]) => String(v || "").trim()).map(([k, v]) => ({ source: k, notes: String(v).slice(0, 1000) }));
  return {
    suppliedSources: active.map((x) => x.source),
    sourceCount: active.length,
    notes: active,
    limitation: active.length ? "Discovery notes supplied by user were included as qualitative evidence." : "No workshop/interview/observation notes were supplied. Outputs are platform-evidence drafts only."
  };
}


function statNumber(stats, field) {
  const n = Number(stats?.[field]);
  return Number.isFinite(n) ? n : 0;
}

function metricStats(metrics, name) {
  const m = metrics?.[name];
  if (!m || typeof m !== "object") return {};
  return m;
}

function metricCount(metrics, name) {
  const s = metricStats(metrics, name);
  return statNumber(s, "count") || statNumber(s, "sum") || statNumber(s, "numerator");
}

function metricSumMs(metrics, name) {
  return statNumber(metricStats(metrics, name), "sum");
}

function metricAverageSeconds(metrics, name) {
  const s = metricStats(metrics, name);
  const count = statNumber(s, "count");
  const sum = statNumber(s, "sum");
  return count > 0 && sum > 0 ? Math.round((sum / count) / 100) / 10 : null;
}

function percent(numerator, denominator) {
  const n = Number(numerator) || 0;
  const d = Number(denominator) || 0;
  return d > 0 ? Math.round((n / d) * 1000) / 10 : null;
}

function normalizeMediaTypes(mediaTypes, mediaType) {
  const raw = mediaTypes != null ? mediaTypes : mediaType;
  const arr = Array.isArray(raw) ? raw : String(raw || "").split(",");
  return arr.map((x) => String(x || "").trim()).filter(Boolean);
}

function buildAggregateFilter({ queueIds = [], userIds = [], mediaTypes = [], direction } = {}) {
  const clauses = [];
  const qids = safeArray(queueIds).map((x) => String(x).trim()).filter(Boolean);
  const uids = safeArray(userIds).map((x) => String(x).trim()).filter(Boolean);
  const mts = safeArray(mediaTypes).map((x) => String(x).trim()).filter(Boolean);
  if (qids.length) clauses.push({ type: "or", predicates: qids.slice(0, 300).map((id) => ({ dimension: "queueId", value: id })) });
  if (uids.length) clauses.push({ type: "or", predicates: uids.slice(0, 300).map((id) => ({ dimension: "userId", value: id })) });
  if (mts.length) clauses.push({ type: "or", predicates: mts.map((m) => ({ dimension: "mediaType", value: m })) });
  if (direction) clauses.push({ type: "and", predicates: [{ dimension: "direction", value: String(direction) }] });
  if (!clauses.length) return undefined;
  if (clauses.length === 1) return clauses[0];
  return { type: "and", clauses };
}

function blueprintMetricsQuery({ interval, startDate, endDate, days = 30, groupBy = [], granularity, queueIds = [], userIds = [], mediaTypes, mediaType, direction, metrics } = {}) {
  const body = {
    interval: normalizeInterval({ interval, startDate, endDate, days }),
    metrics: metrics || ["nOffered", "tAnswered", "tAbandon", "nTransferred", "tWait", "tTalk", "tHeld", "tAcw", "tHandle"],
    groupBy: safeArray(groupBy).filter(Boolean)
  };
  if (granularity) body.granularity = String(granularity);
  const filter = buildAggregateFilter({ queueIds, userIds, mediaTypes: normalizeMediaTypes(mediaTypes, mediaType), direction });
  if (filter) body.filter = filter;
  return body;
}

function summarizeMetricRow(row, lookup = {}) {
  const metrics = row?.metrics || {};
  const offered = metricCount(metrics, "nOffered");
  const answered = metricCount(metrics, "tAnswered");
  const abandoned = metricCount(metrics, "tAbandon");
  const transferred = metricCount(metrics, "nTransferred");
  const handleCount = metricCount(metrics, "tHandle");
  const queueId = row?.group?.queueId;
  const userId = row?.group?.userId;
  return compactObject({
    queueId,
    queueName: queueId ? lookup.queueNamesById?.[queueId] : undefined,
    userId,
    userName: userId ? lookup.userNamesById?.[userId] : undefined,
    mediaType: row?.group?.mediaType,
    direction: row?.group?.direction,
    offered,
    answered,
    abandoned,
    transferred,
    abandonRatePct: percent(abandoned, offered),
    transferRatePct: percent(transferred, offered || answered),
    answerRatePct: percent(answered, offered),
    avgSpeedAnswerSec: metricAverageSeconds(metrics, "tAnswered"),
    avgWaitSec: metricAverageSeconds(metrics, "tWait"),
    avgTalkSec: metricAverageSeconds(metrics, "tTalk"),
    avgHoldSec: metricAverageSeconds(metrics, "tHeld"),
    avgAcwSec: metricAverageSeconds(metrics, "tAcw"),
    avgHandleSec: metricAverageSeconds(metrics, "tHandle"),
    handleCount,
    rawMetrics: metrics
  });
}

function sumMetricRows(rows) {
  const totals = { offered: 0, answered: 0, abandoned: 0, transferred: 0 };
  const weighted = {
    avgSpeedAnswerSec: { total: 0, count: 0 },
    avgWaitSec: { total: 0, count: 0 },
    avgTalkSec: { total: 0, count: 0 },
    avgHoldSec: { total: 0, count: 0 },
    avgAcwSec: { total: 0, count: 0 },
    avgHandleSec: { total: 0, count: 0 }
  };
  for (const r of safeArray(rows)) {
    totals.offered += Number(r.offered) || 0;
    totals.answered += Number(r.answered) || 0;
    totals.abandoned += Number(r.abandoned) || 0;
    totals.transferred += Number(r.transferred) || 0;
    const count = Number(r.handleCount || r.answered || r.offered) || 0;
    for (const k of Object.keys(weighted)) {
      const v = Number(r[k]);
      if (Number.isFinite(v) && count > 0) {
        weighted[k].total += v * count;
        weighted[k].count += count;
      }
    }
  }
  for (const [k, v] of Object.entries(weighted)) totals[k] = v.count > 0 ? Math.round((v.total / v.count) * 10) / 10 : null;
  totals.abandonRatePct = percent(totals.abandoned, totals.offered);
  totals.transferRatePct = percent(totals.transferred, totals.offered || totals.answered);
  totals.answerRatePct = percent(totals.answered, totals.offered);
  return totals;
}

async function resolveQueueIdsForMetrics(token, { queueIds = [], queueNames = [], matchType = "CONTAINS", pageSize = 100, maxPages = 20 } = {}) {
  const ids = new Set(safeArray(queueIds).map((x) => String(x).trim()).filter(Boolean));
  const names = safeArray(queueNames).map((x) => String(x).trim()).filter(Boolean);
  const queueLookup = {};
  if (names.length) {
    const queues = await fetchAllPages(token, "/api/v2/routing/queues", Math.min(500, Math.max(1, Number(pageSize) || 100)), Math.max(1, Number(maxPages) || 20));
    for (const q of queues) {
      for (const name of names) {
        if (matches(q?.name, name, matchType)) {
          ids.add(q.id);
          queueLookup[q.id] = q.name;
        }
      }
    }
  }
  return { queueIds: Array.from(ids), queueLookup };
}

async function buildQueueNameLookup(token, queueIds = []) {
  const unique = Array.from(new Set(safeArray(queueIds).filter(Boolean)));
  const out = {};
  await mapLimit(unique.slice(0, 300), Number(API_CONCURRENCY_LIMIT) || 4, async (id) => {
    try {
      const q = await gcGet(`/api/v2/routing/queues/${encodeURIComponent(id)}`, token);
      out[id] = q?.name || id;
    } catch { out[id] = id; }
  });
  return out;
}

async function buildUserNameLookup(token, userIds = []) {
  const unique = Array.from(new Set(safeArray(userIds).filter(Boolean)));
  const out = {};
  await mapLimit(unique.slice(0, 300), Number(API_CONCURRENCY_LIMIT) || 4, async (id) => {
    try {
      const u = await gcGet(`/api/v2/users/${encodeURIComponent(id)}`, token);
      out[id] = u?.name || u?.email || u?.username || id;
    } catch { out[id] = id; }
  });
  return out;
}

async function runBlueprintAggregate(token, args = {}, groupBy = [], extra = {}) {
  const body = blueprintMetricsQuery({ ...args, ...extra, groupBy });
  const res = await gcPost("/api/v2/analytics/conversations/aggregates/query", token, body);
  return { query: body, rows: flattenAggregateMetrics(res?.results) };
}

export async function gcBlueprintMetricsPackTool({
  interval,
  startDate,
  endDate,
  days = 30,
  mediaType,
  mediaTypes,
  direction,
  queueIds = [],
  queueNames = [],
  userIds = [],
  matchType = "CONTAINS",
  includeChannelMetrics = true,
  includeQueueMetrics = true,
  includeAgentMetrics = false,
  includeTrendMetrics = false,
  trendGranularity = "P1D",
  topN = 20,
  pageSize = 100,
  maxPages = 20
} = {}) {
  const token = await getAccessToken();
  const resolvedQueues = await resolveQueueIdsForMetrics(token, { queueIds, queueNames, matchType, pageSize, maxPages });
  const baseArgs = { interval, startDate, endDate, days, mediaType, mediaTypes, direction, queueIds: resolvedQueues.queueIds, userIds };
  const intervalUsed = normalizeInterval({ interval, startDate, endDate, days });
  const sections = {};
  const errors = [];

  try {
    const overall = await runBlueprintAggregate(token, baseArgs, ["mediaType"]);
    const rows = overall.rows.map((r) => summarizeMetricRow(r));
    sections.overallByMediaType = { query: overall.query, rows, totals: sumMetricRows(rows) };
  } catch (e) { errors.push({ section: "overallByMediaType", error: String(e?.message || e) }); }

  if (includeChannelMetrics) {
    try {
      const channel = await runBlueprintAggregate(token, baseArgs, ["mediaType", "direction"]);
      const rows = channel.rows.map((r) => summarizeMetricRow(r));
      sections.channelUsage = { query: channel.query, rows, totals: sumMetricRows(rows) };
    } catch (e) { errors.push({ section: "channelUsage", error: String(e?.message || e) }); }
  }

  if (includeQueueMetrics) {
    try {
      const queue = await runBlueprintAggregate(token, baseArgs, ["queueId", "mediaType"]);
      const queueIdsFound = queue.rows.map((r) => r?.group?.queueId).filter(Boolean);
      const queueNamesById = { ...resolvedQueues.queueLookup, ...(await buildQueueNameLookup(token, queueIdsFound)) };
      const rows = queue.rows.map((r) => summarizeMetricRow(r, { queueNamesById })).sort((a, b) => (Number(b.offered)||0) - (Number(a.offered)||0));
      sections.queueMetrics = { query: queue.query, rows: rows.slice(0, Math.max(1, Number(topN) || 20)), totalRows: rows.length, totals: sumMetricRows(rows) };
    } catch (e) { errors.push({ section: "queueMetrics", error: String(e?.message || e) }); }
  }

  if (includeAgentMetrics) {
    try {
      const agent = await runBlueprintAggregate(token, baseArgs, ["userId", "mediaType"]);
      const userIdsFound = agent.rows.map((r) => r?.group?.userId).filter(Boolean);
      const userNamesById = await buildUserNameLookup(token, userIdsFound);
      const rows = agent.rows.map((r) => summarizeMetricRow(r, { userNamesById })).sort((a, b) => (Number(b.answered)||0) - (Number(a.answered)||0));
      sections.agentMetrics = { query: agent.query, rows: rows.slice(0, Math.max(1, Number(topN) || 20)), totalRows: rows.length, totals: sumMetricRows(rows) };
    } catch (e) { errors.push({ section: "agentMetrics", error: String(e?.message || e) }); }
  }

  if (includeTrendMetrics) {
    try {
      const trend = await runBlueprintAggregate(token, baseArgs, ["mediaType"], { granularity: trendGranularity });
      const rows = trend.rows.map((r) => summarizeMetricRow(r));
      sections.trendMetrics = { query: trend.query, rows, totals: sumMetricRows(rows), granularity: trendGranularity };
    } catch (e) { errors.push({ section: "trendMetrics", error: String(e?.message || e) }); }
  }

  const metricSummary = sections.overallByMediaType?.totals || sections.channelUsage?.totals || sections.queueMetrics?.totals || {};
  const topQueues = safeArray(sections.queueMetrics?.rows).slice(0, 10).map((r) => ({ queueName: r.queueName || r.queueId, mediaType: r.mediaType, offered: r.offered, answered: r.answered, abandoned: r.abandoned, abandonRatePct: r.abandonRatePct, transferRatePct: r.transferRatePct, avgHandleSec: r.avgHandleSec }));
  const channelMix = safeArray(sections.overallByMediaType?.rows).map((r) => ({ mediaType: r.mediaType || "unknown", offered: r.offered, answered: r.answered, offeredSharePct: percent(r.offered, metricSummary.offered), abandonRatePct: r.abandonRatePct, transferRatePct: r.transferRatePct }));

  return {
    generatedAt: new Date().toISOString(),
    reportType: "Channel Blueprint Metrics and Statistics Pack",
    version: BLUEPRINT_VERSION,
    interval: intervalUsed,
    filters: { mediaType, mediaTypes: normalizeMediaTypes(mediaTypes, mediaType), direction, queueIds: resolvedQueues.queueIds, queueNames, userIds },
    summary: compactObject({
      offered: metricSummary.offered,
      answered: metricSummary.answered,
      abandoned: metricSummary.abandoned,
      transferred: metricSummary.transferred,
      answerRatePct: metricSummary.answerRatePct,
      abandonRatePct: metricSummary.abandonRatePct,
      transferRatePct: metricSummary.transferRatePct,
      avgSpeedAnswerSec: metricSummary.avgSpeedAnswerSec,
      avgWaitSec: metricSummary.avgWaitSec,
      avgTalkSec: metricSummary.avgTalkSec,
      avgHoldSec: metricSummary.avgHoldSec,
      avgAcwSec: metricSummary.avgAcwSec,
      avgHandleSec: metricSummary.avgHandleSec
    }),
    channelMix,
    topQueues,
    sections,
    errors,
    notes: [
      "Statistics are based on Genesys Cloud analytics aggregate metrics for the selected interval and filters.",
      "Use the same interval, timezone assumptions, media filters, and queue filters when comparing to Genesys UI reports.",
      "Authentication, knowledge dependency, and operational workaround findings still require discovery evidence such as call listening or workshops."
    ]
  };
}

export async function gcBlueprintChannelStatisticsTool(args = {}) {
  const pack = await gcBlueprintMetricsPackTool({ ...args, includeQueueMetrics: false, includeAgentMetrics: false, includeTrendMetrics: args.includeTrendMetrics ?? true });
  return {
    generatedAt: new Date().toISOString(),
    section: "Blueprint Channel Usage Metrics",
    interval: pack.interval,
    summary: pack.summary,
    channelMix: pack.channelMix,
    channelUsageRows: pack.sections?.channelUsage?.rows || [],
    trendMetrics: pack.sections?.trendMetrics || undefined,
    errors: pack.errors,
    notes: pack.notes
  };
}

export async function gcBlueprintQueueStatisticsTool(args = {}) {
  const pack = await gcBlueprintMetricsPackTool({ ...args, includeChannelMetrics: false, includeQueueMetrics: true, includeAgentMetrics: false, includeTrendMetrics: args.includeTrendMetrics ?? false });
  return {
    generatedAt: new Date().toISOString(),
    section: "Blueprint Queue Metrics",
    interval: pack.interval,
    summary: pack.summary,
    topQueues: pack.topQueues,
    queueRows: pack.sections?.queueMetrics?.rows || [],
    errors: pack.errors,
    notes: pack.notes
  };
}

export async function gcBlueprintExportMetricsCsvTool(args = {}) {
  const pack = await gcBlueprintMetricsPackTool(args || {});
  const rows = [];
  for (const r of safeArray(pack.sections?.overallByMediaType?.rows)) rows.push({ section: "overallByMediaType", ...r });
  for (const r of safeArray(pack.sections?.channelUsage?.rows)) rows.push({ section: "channelUsage", ...r });
  for (const r of safeArray(pack.sections?.queueMetrics?.rows)) rows.push({ section: "queueMetrics", ...r });
  for (const r of safeArray(pack.sections?.agentMetrics?.rows)) rows.push({ section: "agentMetrics", ...r });
  for (const r of safeArray(pack.sections?.trendMetrics?.rows)) rows.push({ section: "trendMetrics", ...r });
  const fields = ["section", "queueName", "queueId", "userName", "userId", "mediaType", "direction", "offered", "answered", "abandoned", "transferred", "answerRatePct", "abandonRatePct", "transferRatePct", "avgSpeedAnswerSec", "avgWaitSec", "avgTalkSec", "avgHoldSec", "avgAcwSec", "avgHandleSec"];
  const parser = new Json2csvParser({ fields });
  return { generatedAt: new Date().toISOString(), interval: pack.interval, rowCount: rows.length, csv: rows.length ? parser.parse(rows) : "" };
}

export function gcBlueprintAssessmentMapTool() {
  return {
    version: BLUEPRINT_VERSION,
    template: "Channel Blueprint – Discovery Findings & Operational Observations",
    principle: "Use MCP outputs as platform evidence and first-draft observations. Final discovery findings should be validated with workshops, interviews, agent observations, journey walkthroughs, and call listening.",
    sections: BLUEPRINT_SECTION_MAP,
    blueprintTools: [
      "gc_blueprint_assessment_map",
      "gc_blueprint_evidence_pack",
      "gc_blueprint_metrics_pack",
      "gc_blueprint_channel_statistics",
      "gc_blueprint_queue_statistics",
      "gc_blueprint_export_metrics_csv",
      "gc_blueprint_member_journey_observations",
      "gc_blueprint_agent_team_leader_observations",
      "gc_blueprint_channel_routing_observations",
      "gc_blueprint_governance_observations",
      "gc_blueprint_emerging_themes",
      "gc_blueprint_opportunity_summary",
      "gc_blueprint_discovery_summary",
      "gc_blueprint_export_markdown",
      "gc_blueprint_export_docx_payload"
    ]
  };
}

export async function gcBlueprintEvidencePackTool({
  assessmentPeriod,
  preparedFor,
  preparedBy,
  objectTypes,
  pageSize = 100,
  maxPages = 5,
  staleDays = 365,
  includeConversations = false,
  conversationArgs = {},
  includeMetrics = true,
  metricsArgs = {},
  includeFlowComponents = true,
  archyYamlDirectory,
  maxFlows = 50,
  limitFindings = 50,
  discoveryNotes = {}
} = {}) {
  const generatedAt = new Date().toISOString();
  const [orgSummary, auditSummary, objectAudit] = await Promise.all([
    gcOrgSummaryTool({ pageSize, maxPages, includeSamples: true }).catch((e) => ({ error: String(e?.message || e) })),
    gcAuditReportSummaryTool({ includeConversations, conversationArgs, maxPages, limitFindings }).catch((e) => ({ error: String(e?.message || e) })),
    gcAuditAllObjectsTool({ objectTypes, pageSize, maxPages, staleDays, includeFlowAudit: includeFlowComponents, archyYamlDirectory, maxFlows, limitFindings }).catch((e) => ({ error: String(e?.message || e) }))
  ]);

  let metricsPack = null;
  if (includeMetrics) {
    metricsPack = await gcBlueprintMetricsPackTool({
      days: Number(metricsArgs?.days ?? conversationArgs?.days ?? 30),
      interval: metricsArgs?.interval ?? conversationArgs?.interval,
      startDate: metricsArgs?.startDate ?? conversationArgs?.startDate,
      endDate: metricsArgs?.endDate ?? conversationArgs?.endDate,
      mediaType: metricsArgs?.mediaType ?? conversationArgs?.mediaType,
      mediaTypes: metricsArgs?.mediaTypes,
      direction: metricsArgs?.direction ?? conversationArgs?.direction,
      queueIds: metricsArgs?.queueIds,
      queueNames: metricsArgs?.queueNames,
      userIds: metricsArgs?.userIds,
      includeQueueMetrics: metricsArgs?.includeQueueMetrics !== false,
      includeChannelMetrics: metricsArgs?.includeChannelMetrics !== false,
      includeTrendMetrics: metricsArgs?.includeTrendMetrics ?? false,
      includeAgentMetrics: metricsArgs?.includeAgentMetrics ?? false,
      topN: metricsArgs?.topN ?? 15
    }).catch((e) => ({ error: String(e?.message || e) }));
  }

  let flowComponents = null;
  if (includeFlowComponents) {
    flowComponents = await gcCollectFlowComponentsTool({ pageSize, maxPages, maxFlows, archyYamlDirectory, includeMatrix: true }).catch((e) => ({ error: String(e?.message || e) }));
  }

  let conversationAudit = null;
  if (includeConversations) {
    conversationAudit = await gcDisconnectReasonAuditTool({ maxPages: 3, pageSize: 100, ...conversationArgs }).catch((e) => ({ error: String(e?.message || e) }));
  }

  const findings = sortFindings(collectAllFindingsFromEvidence({ auditSummary, objectAudit, flowComponents, conversationAudit, metricsPack })).slice(0, Math.max(1, Number(limitFindings) || 50));
  return {
    generatedAt,
    reportType: "Channel Blueprint Evidence Pack",
    version: BLUEPRINT_VERSION,
    assessmentPeriod,
    preparedFor,
    preparedBy,
    discoveryEvidence: discoveryEvidenceSummary(discoveryNotes),
    platformEvidence: {
      orgSummary,
      auditSummary,
      objectAudit,
      flowComponents,
      conversationAudit,
      metricsPack
    },
    topFindings: findings,
    findingSummary: findingSummary(findings),
    blueprintMapping: BLUEPRINT_SECTION_MAP.map((s) => ({ section: s.section, coverage: s.mcpCoverage, tools: s.primaryTools })),
    limitations: [
      "MCP evidence describes platform configuration and analytics patterns; it does not replace workshop, interview, agent observation, journey walkthrough, or call listening evidence.",
      "Deep flow component extraction is strongest when Archy YAML is supplied through archyYamlDirectory, archyYamlPath, or yamlText.",
      "Conversation and transcript observations depend on analytics, recording, and Speech/Text Analytics availability and permissions.",
      "Metrics/statistics are generated from analytics aggregate/detail APIs for the selected interval and may differ from UI reports if filters, timezone, or interval boundaries differ."
    ]
  };
}

export async function gcBlueprintMemberJourneyObservationsTool(args = {}) {
  const {
    evidencePack,
    discoveryNotes = {},
    interval,
    days = 7,
    queueId,
    queueName,
    mediaType = "voice",
    maxPages = 3,
    archyYamlDirectory,
    maxFlows = 50
  } = args || {};

  const ep = evidencePack || await gcBlueprintEvidencePackTool({ includeConversations: true, conversationArgs: { interval, days, queueId, queueName, mediaType, maxPages }, includeFlowComponents: true, archyYamlDirectory, maxFlows, maxPages });
  const findings = collectAllFindingsFromEvidence(ep);
  const flowRows = safeArray(ep.platformEvidence?.flowComponents?.flowRows);
  const transferFindings = selectFindingsByKeywords(findings, ["transfer", "queue hop", "routing", "acd", "disconnect", "wrap"], 5);
  const flowFindings = selectFindingsByKeywords(findings, ["flow", "queue", "priority", "skill", "unresolved"], 5);
  const conversationFindings = selectFindingsByKeywords(findings, ["conversation", "disconnect", "peer", "abandon", "wait", "hold"], 5);

  return {
    generatedAt: new Date().toISOString(),
    section: "2 Member Journey Observations",
    evidenceMode: ep.discoveryEvidence?.sourceCount ? "Platform evidence + supplied discovery notes" : "Platform evidence only",
    discoveryEvidence: discoveryEvidenceSummary(discoveryNotes),
    assessorObservations: {
      entryComplexity: observationsFromFindings("Entry complexity", flowFindings, "No strong platform finding for entry complexity was returned. Validate IVR entry paths, member language, and manual triage through journey walkthroughs and call listening."),
      authenticationFriction: [{
        observation: "Authentication friction cannot be confirmed from configuration data alone unless authentication actions are visible in exported flow YAML, transcripts, or discovery notes.",
        evidence: ep.discoveryEvidence?.sourceCount ? "Supplied discovery notes may contain authentication observations." : "Requires call listening, journey walkthrough, transcript, or workshop evidence.",
        evidenceStrength: ep.discoveryEvidence?.sourceCount ? "Discovery evidence supplied" : "Requires discovery validation",
        recommendedDiscoveryFollowUp: "Check whether members are re-authenticated after transfers and whether authentication context passes between teams."
      }],
      transferBehaviour: observationsFromFindings("Transfer behaviour", transferFindings, "No transfer-specific finding was returned for the selected scope. Validate transfer behaviour through conversation timelines and queue-level analytics."),
      escalationPoints: observationsFromFindings("Escalation points", selectFindingsByKeywords(findings, ["skill", "specialist", "supervisor", "hold", "transfer", "queue"], 5), "No clear escalation pattern was detected from platform evidence. Validate through call listening and team leader interviews."),
      selfServiceObservations: observationsFromFindings("Self-service observations", conversationFindings, "Self-service opportunity evidence usually requires contact reason/topic analysis, transcripts, call listening, or agent observations.")
    },
    usefulEvidence: {
      flowRowsSample: flowRows.slice(0, 10),
      topFindings: safeSlice(findings, 10).map((f, i) => findingToBlueprintFinding(f, i))
    },
    limitations: ["Authentication, member frustration, and restated context need qualitative evidence unless transcripts are available."]
  };
}

export async function gcBlueprintAgentTeamLeaderObservationsTool(args = {}) {
  const {
    evidencePack,
    discoveryNotes = {},
    interval,
    days = 7,
    queueId,
    queueName,
    mediaType = "voice",
    maxPages = 3,
    maxQueues = 25,
    includeRecentAdminActivity = true
  } = args || {};

  const ep = evidencePack || await gcBlueprintEvidencePackTool({ includeConversations: true, conversationArgs: { interval, days, queueId, queueName, mediaType, maxPages }, maxPages });
  const findings = collectAllFindingsFromEvidence(ep);
  const routingAudit = await gcAuditRoutingTool({ maxQueues, includeMemberSkills: true, limitFindings: 100 }).catch((e) => ({ error: String(e?.message || e) }));
  const adminActivity = includeRecentAdminActivity ? await gcAuditRecentAdminActivityTool({ days, pageSize: 100 }).catch((e) => ({ error: String(e?.message || e) })) : null;
  const combined = [...findings, ...safeArray(routingAudit.findings), ...safeArray(adminActivity?.findings)];

  return {
    generatedAt: new Date().toISOString(),
    section: "3 Agent & Team Leader Observations",
    evidenceMode: discoveryEvidenceSummary(discoveryNotes).sourceCount ? "Platform evidence + supplied discovery notes" : "Platform evidence only",
    discoveryEvidence: discoveryEvidenceSummary(discoveryNotes),
    assessorObservations: {
      manualIntervention: observationsFromFindings("Manual intervention", selectFindingsByKeywords(combined, ["change", "queue", "member", "routing", "staff"], 5), "Manual intervention is usually not directly visible unless changes are reflected in audit events or queue staffing patterns. Validate with team leader interviews."),
      knowledgeDependency: observationsFromFindings("Knowledge dependency", selectFindingsByKeywords(combined, ["skill", "hold", "transfer", "specialist", "wrap"], 5), "Knowledge dependency usually requires agent observation, call listening, or transcript evidence."),
      queueManagementBehaviour: observationsFromFindings("Queue management behaviour", selectFindingsByKeywords(combined, ["queue", "member", "staff", "routing", "skill"], 5), "No queue-management finding was returned in the selected scope."),
      escalationBehaviour: observationsFromFindings("Escalation behaviour", selectFindingsByKeywords(combined, ["transfer", "supervisor", "skill", "hold", "queue hop"], 5), "No escalation pattern was confirmed from platform evidence."),
      holdDrivers: observationsFromFindings("Hold drivers", selectFindingsByKeywords(combined, ["hold", "held", "wait", "conversation"], 5), "Hold reason cannot be confirmed from metrics alone; validate through call listening/transcripts.")
    },
    supportingData: { routingAudit, adminActivity },
    limitations: ["The tool can identify staffing, routing, hold, and change patterns; it cannot observe informal conversations or messaging workarounds unless provided in notes."]
  };
}

export async function gcBlueprintChannelRoutingObservationsTool(args = {}) {
  const {
    evidencePack,
    discoveryNotes = {},
    archyYamlDirectory,
    maxFlows = 100,
    maxPages = 5,
    includeQueueMemberCounts = true,
    includeChannelUsage = false,
    conversationArgs = {}
  } = args || {};

  const ep = evidencePack || await gcBlueprintEvidencePackTool({ includeFlowComponents: true, archyYamlDirectory, maxFlows, maxPages, includeConversations: includeChannelUsage, conversationArgs });
  const findings = collectAllFindingsFromEvidence(ep);
  const flowComponents = ep.platformEvidence?.flowComponents || await gcCollectFlowComponentsTool({ archyYamlDirectory, maxFlows, maxPages, includeQueueMemberCounts, includeMatrix: true }).catch((e) => ({ error: String(e?.message || e) }));
  const queueAudit = await gcAuditQueuesTool({ maxPages, includeMemberCounts: true, limitFindings: 100 }).catch((e) => ({ error: String(e?.message || e) }));

  return {
    generatedAt: new Date().toISOString(),
    section: "4 Channel & Routing Observations",
    evidenceMode: discoveryEvidenceSummary(discoveryNotes).sourceCount ? "Platform evidence + supplied discovery notes" : "Platform evidence only",
    discoveryEvidence: discoveryEvidenceSummary(discoveryNotes),
    assessorObservations: {
      intentVsOrganisation: observationsFromFindings("Intent vs organisation", selectFindingsByKeywords(findings, ["queue", "flow", "transfer", "routing"], 5), "Assess whether queue names and flow paths reflect member intent or internal team structures."),
      whyQueuesExist: observationsFromFindings("Why queues exist", selectFindingsByKeywords([...findings, ...safeArray(queueAudit.findings)], ["queue", "stale", "description", "no members", "lifecycle"], 5), "Queue origin and purpose require team leader/platform owner validation, especially for low-volume or legacy queues."),
      routingDecisionMaking: observationsFromFindings("Routing decision-making", selectFindingsByKeywords(findings, ["change", "flow", "routing", "priority", "skill"], 5), "Decision-making process requires governance/workshop validation; MCP can show current routing configuration and change history."),
      specialisedPathways: observationsFromFindings("Specialised pathways", selectFindingsByKeywords(findings, ["skill", "specialist", "priority", "queue", "flow"], 5), "No specialist routing pattern was found in platform evidence for the selected scope."),
      operationalWorkarounds: observationsFromFindings("Operational workarounds", selectFindingsByKeywords(findings, ["manual", "change", "routing", "queue", "workaround"], 5), "Operational workarounds normally require workshop or observation evidence unless reflected in repeated platform changes.")
    },
    channelUsageObservations: includeChannelUsage ? ep.platformEvidence?.conversationAudit : { note: "Set includeChannelUsage=true with conversationArgs to include analytics-backed channel usage observations." },
    flowComponentSummary: {
      count: flowComponents?.count,
      matrixSample: safeSlice(flowComponents?.matrix, 25),
      rowsSample: safeSlice(flowComponents?.flowRows, 25),
      error: flowComponents?.error
    },
    supportingData: { queueAudit }
  };
}

export async function gcBlueprintGovernanceObservationsTool(args = {}) {
  const {
    evidencePack,
    discoveryNotes = {},
    days = 14,
    objectTypes = ["users", "roles", "queues", "flows", "oauthClients", "dataActions", "integrations"],
    maxPages = 5,
    includeChangeHistory = true
  } = args || {};

  const ep = evidencePack || await gcBlueprintEvidencePackTool({ objectTypes, maxPages, includeFlowComponents: false });
  const findings = collectAllFindingsFromEvidence(ep);
  const [roles, oauthClients, adminActivity, lifecycle] = await Promise.all([
    gcAuditRolesTool({ maxPages, limitFindings: 100 }).catch((e) => ({ error: String(e?.message || e) })),
    gcOauthClientsTool({ pageSize: 100 }).catch((e) => ({ error: String(e?.message || e) })),
    includeChangeHistory ? gcAuditRecentAdminActivityTool({ days, pageSize: 100 }).catch((e) => ({ error: String(e?.message || e) })) : Promise.resolve(null),
    gcAuditObjectLifecycleTool({ objectTypes, maxPages, limitFindings: 100 }).catch((e) => ({ error: String(e?.message || e) }))
  ]);
  const combined = [...findings, ...safeArray(roles.findings), ...safeArray(lifecycle.findings), ...safeArray(adminActivity?.findings)];

  return {
    generatedAt: new Date().toISOString(),
    section: "5 Platform Ownership & Governance Observations",
    evidenceMode: discoveryEvidenceSummary(discoveryNotes).sourceCount ? "Platform evidence + supplied discovery notes" : "Platform evidence only",
    discoveryEvidence: discoveryEvidenceSummary(discoveryNotes),
    assessorObservations: {
      platformOwnership: observationsFromFindings("Platform ownership", selectFindingsByKeywords(combined, ["role", "admin", "oauth", "permission", "access"], 5), "Platform ownership cannot be fully determined from permissions alone; validate who approves and owns routine changes."),
      changeManagement: observationsFromFindings("Change management", selectFindingsByKeywords(combined, ["change", "audit", "modified", "stale", "lifecycle"], 5), "Change process maturity requires workshop/interview evidence; MCP can show recent object change patterns where Audit API data is available."),
      dependencyRisks: observationsFromFindings("Dependency risks", selectFindingsByKeywords(combined, ["admin", "role", "permission", "oauth", "change"], 5), "Validate whether a small group or single person holds routing/IVR knowledge and change authority."),
      standardsAndConsistency: observationsFromFindings("Standards and consistency", selectFindingsByKeywords(combined, ["description", "division", "naming", "stale", "lifecycle", "object"], 5), "No standards-specific finding was returned; validate naming conventions, descriptions, and ownership fields across objects.")
    },
    supportingData: { roles, oauthClients, adminActivity, lifecycle }
  };
}

export async function gcBlueprintEmergingThemesTool({ evidencePack, discoveryNotes = {}, maxThemes = 5, includeEvidencePack = false } = {}) {
  const ep = evidencePack || await gcBlueprintEvidencePackTool({ includeConversations: false, includeFlowComponents: true, limitFindings: 100 });
  const findings = collectAllFindingsFromEvidence(ep);
  const themes = inferBlueprintThemes(findings, { maxThemes });
  return {
    generatedAt: new Date().toISOString(),
    section: "6 Emerging Themes",
    discoveryEvidence: discoveryEvidenceSummary(discoveryNotes),
    themes,
    assessorGuidance: "Use these as candidate themes. A final theme should be visible in multiple sections and supported by both qualitative discovery evidence and platform evidence where possible.",
    evidencePack: includeEvidencePack ? ep : undefined
  };
}

export async function gcBlueprintOpportunitySummaryTool({ evidencePack, discoveryNotes = {}, maxOpportunities = 12, includeEvidencePack = false } = {}) {
  const ep = evidencePack || await gcBlueprintEvidencePackTool({ includeConversations: false, includeFlowComponents: true, limitFindings: 100 });
  const findings = collectAllFindingsFromEvidence(ep);
  const opportunities = inferBlueprintOpportunities(findings, { maxOpportunities });
  const furtherInvestigation = [];
  if (!ep.platformEvidence?.conversationAudit || ep.platformEvidence?.conversationAudit?.error) furtherInvestigation.push({ opportunityArea: "Member Journey Analytics", whatIsUnknown: "Conversation patterns, transfer drivers, and call outcomes may not be fully available in this evidence pack.", suggestedNextStep: "Run conversation audits for a representative date range and validate with call listening." });
  if (!ep.platformEvidence?.flowComponents || ep.platformEvidence?.flowComponents?.error) furtherInvestigation.push({ opportunityArea: "Flow Component Review", whatIsUnknown: "Deep flow component dependencies may be incomplete without Archy YAML.", suggestedNextStep: "Export Architect flows using Archy and rerun gc_collect_flow_components." });
  if (!discoveryEvidenceSummary(discoveryNotes).sourceCount) furtherInvestigation.push({ opportunityArea: "Discovery Evidence", whatIsUnknown: "Workshop, agent observation, and call listening evidence has not been supplied to the MCP.", suggestedNextStep: "Provide discovery notes and rerun the blueprint tools to strengthen findings." });

  return {
    generatedAt: new Date().toISOString(),
    section: "7 Opportunity Summary",
    discoveryEvidence: discoveryEvidenceSummary(discoveryNotes),
    opportunities,
    opportunitiesRequiringFurtherInvestigation: furtherInvestigation,
    assessorGuidance: "Frame opportunities as areas for exploration, not predetermined solutions.",
    evidencePack: includeEvidencePack ? ep : undefined
  };
}

export async function gcBlueprintDiscoverySummaryTool({ evidencePack, discoveryNotes = {}, maxFindings = 5, maxOpportunities = 5 } = {}) {
  const ep = evidencePack || await gcBlueprintEvidencePackTool({ includeConversations: false, includeFlowComponents: true, limitFindings: 100 });
  const findings = sortFindings(collectAllFindingsFromEvidence(ep));
  const topFindings = safeSlice(findings, maxFindings).map((f, i) => findingToBlueprintFinding(f, i));
  const themes = inferBlueprintThemes(findings, { maxThemes: 5 });
  const opportunities = inferBlueprintOpportunities(findings, { maxOpportunities });

  return {
    generatedAt: new Date().toISOString(),
    section: "8 Discovery Summary",
    discoveryEvidence: discoveryEvidenceSummary(discoveryNotes),
    keyStrengths: [{ strength: "Platform evidence is available for structured review through MCP tools.", evidence: "Current MCP outputs provide inventory, audit, flow component, and optional conversation analytics evidence.", designImplication: "Use the data collection layer as the baseline for discovery and future design validation." }],
    keyChallenges: topFindings.map((f) => ({ challenge: f.observation, evidence: f.evidenceSource, impact: f.whyItMatters })),
    keyOpportunities: opportunities.slice(0, maxOpportunities).map((o) => ({ opportunity: o.opportunityArea, evidence: o.evidence, expectedBenefit: o.potentialBenefit })),
    designConsiderations: [
      { designConsideration: "Route around member intent, not only team structure", whatItMeansInPractice: "Review queues and flow paths against member needs and transfer patterns.", evidence: "Use flow component inventory, queue audit, and conversation transfer patterns." },
      { designConsideration: "Simplify before automating", whatItMeansInPractice: "Address queue/flow complexity and stale objects before adding additional automation.", evidence: "Use object lifecycle, stale object, and flow component audit evidence." },
      { designConsideration: "Governance should enable safe routine change", whatItMeansInPractice: "Clarify ownership, standards, and change pathways for queues, flows, schedules, data tables, and roles.", evidence: "Use role impact, OAuth client review, recent admin activity, and object change history." },
      { designConsideration: "Make dependencies visible before change", whatItMeansInPractice: "Use flow component matrices to identify queues, skills, schedules, data tables, data actions, prompts, and wrap-up codes used by flows.", evidence: "Use gc_collect_flow_component_matrix and gc_object_relationships." }
    ],
    candidateThemes: themes,
    assessmentNarrative: [
      "The MCP evidence pack provides a structured current-state view of the Genesys Cloud channel environment, including object inventory, user/role/queue audits, flow component dependencies, and optional conversation analytics.",
      "The strongest platform-supported observations typically relate to channel and routing design, object lifecycle hygiene, queue staffing, flow dependencies, access governance, and conversation patterns. Behavioural observations such as manual workarounds, knowledge dependency, and authentication friction should be validated through workshops, agent observations, journey walkthroughs, and call listening.",
      "The most useful next step is to combine this platform evidence with discovery notes, then finalise themes and opportunities that are supported by more than one source of evidence.",
      "The design phase should use this evidence to prioritise routing simplification, queue rationalisation, flow dependency documentation, governance improvement, and targeted journey review."
    ].join("\n\n")
  };
}

function markdownSectionHeading(level, text) {
  return `${"#".repeat(Math.max(1, Number(level) || 1))} ${text}`;
}

function findingRowsToMarkdown(rows) {
  const out = [];
  for (const r of safeArray(rows)) {
    out.push(`### ${r.findingNumber ? `Finding ${r.findingNumber}` : r.priority || "Observation"}`);
    out.push(`- Observation: ${r.observation || r.challenge || ""}`);
    out.push(`- Evidence / Source: ${r.evidenceSource || r.evidence || ""}`);
    out.push(`- Why It Matters / Impact: ${r.whyItMatters || r.impact || ""}`);
    if (r.priority) out.push(`- Priority: ${r.priority}`);
    out.push("");
  }
  return out.join("\n");
}

export async function gcBlueprintExportMarkdownTool({
  evidencePack,
  discoveryNotes = {},
  includeAssessorGuidance = true,
  includeMetrics = true,
  metricsArgs = {},
  includeConversations = false,
  conversationArgs = {},
  includeFlowComponents = true,
  archyYamlDirectory,
  maxPages = 5,
  maxFlows = 50,
  limitFindings = 100
} = {}) {
  const ep = evidencePack || await gcBlueprintEvidencePackTool({
    discoveryNotes,
    includeMetrics,
    metricsArgs,
    includeConversations,
    conversationArgs,
    includeFlowComponents,
    archyYamlDirectory,
    maxPages,
    maxFlows,
    limitFindings
  });
  const summary = await gcBlueprintDiscoverySummaryTool({ evidencePack: ep, discoveryNotes });
  const metrics = ep?.platformEvidence?.metricsPack || null;
  const themes = await gcBlueprintEmergingThemesTool({ evidencePack: ep, discoveryNotes });
  const opportunities = await gcBlueprintOpportunitySummaryTool({ evidencePack: ep, discoveryNotes });
  const findings = safeArray(summary.keyChallenges).map((x, i) => ({ findingNumber: i + 1, observation: x.challenge, evidenceSource: x.evidence, whyItMatters: x.impact, priority: priorityFromSeverity(collectAllFindingsFromEvidence(ep)[i]?.severity) }));

  const lines = [];
  lines.push(markdownSectionHeading(1, "Channel Blueprint – Discovery Findings Draft"));
  lines.push("");
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`MCP Blueprint Layer: v${BLUEPRINT_VERSION}`);
  lines.push("");
  if (includeAssessorGuidance) {
    lines.push("> This is a draft from platform evidence and supplied discovery notes. Validate all observations with workshops, interviews, agent observations, journey walkthroughs, call listening, and documentation review before client use.");
    lines.push("");
  }
  lines.push(markdownSectionHeading(2, "Platform Metrics and Statistics Snapshot"));
  lines.push("");
  if (metrics?.summary) {
    lines.push(`- Interval: ${metrics.interval || "Not supplied"}`);
    lines.push(`- Offered: ${metrics.summary.offered ?? "N/A"}`);
    lines.push(`- Answered: ${metrics.summary.answered ?? "N/A"}`);
    lines.push(`- Abandoned: ${metrics.summary.abandoned ?? "N/A"}`);
    lines.push(`- Transferred: ${metrics.summary.transferred ?? "N/A"}`);
    lines.push(`- Answer Rate: ${metrics.summary.answerRatePct ?? "N/A"}%`);
    lines.push(`- Abandon Rate: ${metrics.summary.abandonRatePct ?? "N/A"}%`);
    lines.push(`- Transfer Rate: ${metrics.summary.transferRatePct ?? "N/A"}%`);
    lines.push(`- Avg Wait: ${metrics.summary.avgWaitSec ?? "N/A"} sec`);
    lines.push(`- Avg Handle: ${metrics.summary.avgHandleSec ?? "N/A"} sec`);
    if (safeArray(metrics.topQueues).length) {
      lines.push("");
      lines.push("Top queue metrics:");
      for (const q of safeSlice(metrics.topQueues, 10)) lines.push(`- ${q.queueName || q.queueId}: offered ${q.offered ?? "N/A"}, answered ${q.answered ?? "N/A"}, abandon rate ${q.abandonRatePct ?? "N/A"}%, transfer rate ${q.transferRatePct ?? "N/A"}%`);
    }
  } else {
    lines.push("Metrics pack was not included or could not be generated for this draft.");
  }
  lines.push("");
  lines.push(markdownSectionHeading(2, "1. Executive Summary – Key Findings"));
  lines.push("");
  lines.push(findingRowsToMarkdown(findings));
  lines.push(markdownSectionHeading(2, "6. Emerging Themes"));
  lines.push("");
  for (const [i, t] of safeArray(themes.themes).entries()) {
    lines.push(`### Theme ${i + 1}`);
    lines.push(`- Theme Statement: ${t.themeStatement}`);
    lines.push(`- Why It Matters: ${t.whyItMatters}`);
    lines.push(`- Potential Opportunity: ${t.potentialOpportunity}`);
    if (safeArray(t.supportingEvidence).length) {
      lines.push("- Supporting Evidence:");
      for (const e of safeSlice(t.supportingEvidence, 5)) lines.push(`  - ${e.observation || "Evidence"}: ${e.detail || e.evidence || ""}`);
    }
    lines.push("");
  }
  lines.push(markdownSectionHeading(2, "7. Opportunity Summary"));
  lines.push("");
  for (const [i, o] of safeArray(opportunities.opportunities).entries()) {
    lines.push(`### Opportunity ${i + 1}: ${o.opportunityArea}`);
    lines.push(`- Summary: ${o.summary}`);
    lines.push(`- Evidence: ${o.evidence}`);
    lines.push(`- Potential Benefit: ${o.potentialBenefit}`);
    lines.push(`- Priority: ${o.priority}`);
    lines.push("");
  }
  lines.push(markdownSectionHeading(2, "8. Discovery Summary Narrative"));
  lines.push("");
  lines.push(summary.assessmentNarrative);
  lines.push("");
  lines.push(markdownSectionHeading(2, "Evidence Limitations"));
  lines.push("");
  for (const l of safeArray(ep.limitations)) lines.push(`- ${l}`);
  return lines.join("\n");
}

export async function gcBlueprintExportDocxPayloadTool({
  evidencePack,
  discoveryNotes = {},
  includeRawEvidence = false,
  includeMetrics = true,
  metricsArgs = {},
  includeConversations = false,
  conversationArgs = {},
  includeFlowComponents = true,
  archyYamlDirectory,
  maxPages = 5,
  maxFlows = 50,
  limitFindings = 100
} = {}) {
  const ep = evidencePack || await gcBlueprintEvidencePackTool({
    discoveryNotes,
    includeMetrics,
    metricsArgs,
    includeConversations,
    conversationArgs,
    includeFlowComponents,
    archyYamlDirectory,
    maxPages,
    maxFlows,
    limitFindings
  });
  const metricsPack = ep?.platformEvidence?.metricsPack || (includeMetrics
    ? await gcBlueprintMetricsPackTool(metricsArgs || { days: 30 }).catch((e) => ({ error: String(e?.message || e) }))
    : null);
  const memberJourney = await gcBlueprintMemberJourneyObservationsTool({ evidencePack: ep, discoveryNotes });
  const agentTeamLeader = await gcBlueprintAgentTeamLeaderObservationsTool({ evidencePack: ep, discoveryNotes, includeRecentAdminActivity: false }).catch((e) => ({ error: String(e?.message || e) }));
  const channelRouting = await gcBlueprintChannelRoutingObservationsTool({ evidencePack: ep, discoveryNotes }).catch((e) => ({ error: String(e?.message || e) }));
  const governance = await gcBlueprintGovernanceObservationsTool({ evidencePack: ep, discoveryNotes, includeChangeHistory: false }).catch((e) => ({ error: String(e?.message || e) }));
  const themes = await gcBlueprintEmergingThemesTool({ evidencePack: ep, discoveryNotes });
  const opportunities = await gcBlueprintOpportunitySummaryTool({ evidencePack: ep, discoveryNotes });
  const discoverySummary = await gcBlueprintDiscoverySummaryTool({ evidencePack: ep, discoveryNotes });

  return compactObject({
    generatedAt: new Date().toISOString(),
    payloadType: "Channel Blueprint DOCX Fill Payload",
    version: BLUEPRINT_VERSION,
    instructions: "Use this JSON payload to populate the Word assessment template. Review and edit wording before client use.",
    requestOptions: { includeMetrics, includeConversations, includeFlowComponents, metricsArgs, conversationArgs, maxPages, maxFlows, limitFindings },
    sections: {
      section0MetricsAndStatistics: metricsPack,
      section1ExecutiveSummary: {
        metricsSnapshot: metricsPack?.summary || metricsPack,
        keyFindings: discoverySummary.keyChallenges,
        keyOpportunities: discoverySummary.keyOpportunities
      },
      section2MemberJourneyObservations: memberJourney.assessorObservations,
      section3AgentTeamLeaderObservations: agentTeamLeader.assessorObservations || agentTeamLeader,
      section4ChannelRoutingObservations: channelRouting.assessorObservations || channelRouting,
      section5GovernanceObservations: governance.assessorObservations || governance,
      section6EmergingThemes: themes.themes,
      section7OpportunitySummary: opportunities.opportunities,
      section8DiscoverySummary: discoverySummary
    },
    evidenceLimitations: ep.limitations,
    rawEvidencePack: includeRawEvidence ? ep : undefined
  });
}

export async function gcAuditReportSummaryTool({
  includeConversations = false,
  conversationArgs = {},
  maxPages = 10,
  limitFindings = 50
} = {}) {
  const [org, users, roles, queues] = await Promise.all([
    gcOrgSummaryTool({ includeSamples: false }),
    gcAuditUsersTool({ maxPages, limitFindings }),
    gcAuditRolesTool({ maxPages, limitFindings }),
    gcAuditQueuesTool({ maxPages, limitFindings })
  ]);

  let conversations = null;
  if (includeConversations) {
    conversations = await gcDisconnectReasonAuditTool({ maxPages: 3, pageSize: 50, ...conversationArgs });
  }

  const allFindings = [
    ...safeArray(users.findings),
    ...safeArray(roles.findings),
    ...safeArray(queues.findings),
    ...safeArray(conversations?.findings)
  ];
  const topFindings = sortFindings(allFindings).slice(0, Math.max(1, Number(limitFindings) || 50));

  return {
    generatedAt: new Date().toISOString(),
    reportType: "Genesys Cloud Org Audit Summary v1",
    scope: { users: true, roles: true, queues: true, conversations: includeConversations },
    org,
    summary: {
      findingSummary: findingSummary(allFindings),
      scannedUsers: users.scannedUsers,
      scannedRoles: roles.scannedRoles,
      scannedQueues: queues.scannedQueues,
      scannedConversations: conversations?.count
    },
    topFindings,
    sections: { users: users.findingSummary, roles: roles.findingSummary, queues: queues.findingSummary, conversations: conversations?.findingSummary || null },
    recommendations: [
      "Review high and critical findings first, especially inactive users with roles/queues and queues with no members.",
      "Validate OAuth client permissions and division access before using audit results as the final source of truth.",
      "For conversation review, start with disconnect reason and queue conversation audits for a narrow interval, then expand the date range."
    ],
    detail: { users, roles, queues, conversations }
  };
}

export async function gcAuditExportMarkdownTool({ auditResult, includeDetails = false } = {}) {
  const result = auditResult && typeof auditResult === "object" ? auditResult : await gcAuditReportSummaryTool({ includeConversations: false });
  const findings = safeArray(result.topFindings || result.findings || result.detail?.users?.findings || []);
  const summary = result.summary?.findingSummary || result.findingSummary || findingSummary(findings);
  const lines = [];
  lines.push(`# ${result.reportType || "Genesys Cloud Audit Report"}`);
  lines.push("");
  lines.push(`Generated: ${result.generatedAt || new Date().toISOString()}`);
  lines.push("");
  lines.push("## Finding Summary");
  lines.push("");
  lines.push(`- Critical: ${summary.critical || 0}`);
  lines.push(`- High: ${summary.high || 0}`);
  lines.push(`- Medium: ${summary.medium || 0}`);
  lines.push(`- Low: ${summary.low || 0}`);
  lines.push(`- Total: ${summary.total || 0}`);
  lines.push("");
  lines.push("## Top Findings");
  lines.push("");
  if (!findings.length) lines.push("No findings returned for the selected scope.");
  for (const [i, f] of findings.entries()) {
    lines.push(`### ${i + 1}. [${String(f.severity || "info").toUpperCase()}] ${f.title || "Finding"}`);
    lines.push("");
    lines.push(`- Area: ${f.area || "N/A"}`);
    lines.push(`- Detail: ${f.detail || "N/A"}`);
    lines.push(`- Recommendation: ${f.recommendation || "Review and validate."}`);
    if (includeDetails && f.evidence) {
      lines.push("- Evidence:");
      lines.push("```json");
      lines.push(JSON.stringify(f.evidence, null, 2));
      lines.push("```");
    }
    lines.push("");
  }
  if (result.recommendations?.length) {
    lines.push("## General Recommendations");
    lines.push("");
    for (const r of result.recommendations) lines.push(`- ${r}`);
  }
  return lines.join("\n");
}

export async function gcAuditExportCsvTool({ auditResult } = {}) {
  const result = auditResult && typeof auditResult === "object" ? auditResult : await gcAuditReportSummaryTool({ includeConversations: false });
  const findings = safeArray(result.topFindings || result.findings || []);
  const rows = findings.map((f) => ({
    severity: f.severity || "info",
    area: f.area || "",
    title: f.title || "",
    detail: f.detail || "",
    recommendation: f.recommendation || "",
    evidence: f.evidence ? JSON.stringify(f.evidence) : ""
  }));
  const parser = new Json2csvParser({ fields: ["severity", "area", "title", "detail", "recommendation", "evidence"] });
  return parser.parse(rows);
}
