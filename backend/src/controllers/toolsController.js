const mongoose = require('mongoose');

const TOOL_DEFINITIONS = [
  {
    name: 'MISP',
    key: 'misp',
    role: 'Threat Intelligence Platform',
    network: 'SOC',
    icon: 'share',
    collection: 'Misp',
  },
  {
    name: 'Cortex',
    key: 'cortex',
    role: 'Analysis Engine',
    network: 'SOC',
    icon: 'hub',
    collection: 'Cortex',
  },
  {
    name: 'Wazuh',
    key: 'wazuh',
    role: 'SIEM',
    network: 'SOC',
    icon: 'radar',
    collection: 'Wazuh',
  },
  {
    name: 'IRIS',
    key: 'iris',
    role: 'Incident Response Platform',
    network: 'SOC',
    icon: 'security',
    collection: 'Iris',
  },
  {
    name: 'SOAR / n8n',
    key: 'n8n',
    role: 'Security Orchestration',
    network: 'SOC',
    icon: 'auto_fix_high',
    collection: 'n8n',
  },
  {
    name: 'pfSense',
    key: 'pfsense',
    role: 'Firewall & VPN',
    network: 'Gateway',
    icon: 'router',
    collection: 'pfsense',
  },
  {
    name: 'Wazuh Agent',
    key: 'wazuh-agent',
    role: 'Endpoint Agent',
    network: 'SOC',
    icon: 'memory',
    collection: 'Wazuh',
  },
];

const STATUS_FIELDS = ['status', 'tool_status', 'health', 'state', 'iris_status', 'alert_status'];
const TOOL_FIELD_PRIORITY = {
  Cortex: ['_id', 'job_id', 'target_ip', 'vt_malicious', 'vt_reputation', 'is_private'],
  IRIS: ['_id', 'iris_alert_id', 'iris_uuid', 'severity', 'alert_status', 'source_ref'],
  MISP: ['_id', 'event_id', 'src_ip', 'misp_error', 'status'],
  Wazuh: [
    '_id',
    'wazuh_id',
    'timestamp',
    'rule_id',
    'rule_level',
    'rule_description',
    'agent_name',
    'attacker_ip',
    'target_user',
    'full_log',
  ],
  'Wazuh Agent': [
    '_id',
    'wazuh_id',
    'timestamp',
    'rule_id',
    'rule_level',
    'rule_description',
    'agent_name',
    'attacker_ip',
    'target_user',
    'full_log',
  ],
  pfSense: ['_id', 'pfsense_rule_id', 'blocked_ip', 'interface', 'rule_descr', 'tracker'],
};

const toStatus = (doc, hasData) => {
  if (!hasData) return 'OFFLINE';

  for (const field of STATUS_FIELDS) {
    const value = doc?.[field];
    if (value === undefined || value === null) continue;

    const normalized = String(value).trim().toLowerCase();
    if (!normalized) continue;

    if (['online', 'up', 'ok', 'healthy'].includes(normalized)) return 'ONLINE';
    if (['warning'].includes(normalized)) return 'WARNING';
    if (['degraded'].includes(normalized)) return 'DEGRADED';
    if (['offline', 'down', 'disconnected', 'error', 'failed'].includes(normalized)) return 'OFFLINE';

    if (normalized.includes('connected')) return 'ONLINE';
    if (normalized.includes('warning')) return 'WARNING';
    if (normalized.includes('degrad')) return 'DEGRADED';
    if (normalized.includes('disconnect') || normalized.includes('error') || normalized.includes('fail')) {
      return 'OFFLINE';
    }
  }

  return 'ONLINE';
};

const normalizeValue = (value) => {
  if (value === undefined || value === null || value === '') return '-';
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
};

const extractIp = (doc) => {
  const ip = doc?.source_ref || doc?.target_ip || doc?.attacker_ip || doc?.blocked_ip || doc?.src_ip;
  return ip ? String(ip) : undefined;
};

const getLatestDocumentMetrics = (toolName, latestDoc) => {
  if (!latestDoc) {
    return [{ label: 'Latest Data', value: 'No data' }];
  }

  const preferredOrder = TOOL_FIELD_PRIORITY[toolName] ?? ['_id'];
  const rank = new Map(preferredOrder.map((field, index) => [field, index]));

  const entries = Object.entries(latestDoc)
    .filter(([key]) => key !== '__v')
    .sort(([a], [b]) => {
      const ar = rank.has(a) ? rank.get(a) : Number.MAX_SAFE_INTEGER;
      const br = rank.has(b) ? rank.get(b) : Number.MAX_SAFE_INTEGER;
      if (ar !== br) return ar - br;
      return a.localeCompare(b);
    });

  return entries.map(([key, value]) => ({ label: key, value: normalizeValue(value) }));
};

const buildToolCard = async (db, definition, collectionName) => {
  const collection = db.collection(collectionName);
  const count = await collection.countDocuments();
  const latestDoc = await collection.find({}).sort({ _id: -1 }).limit(1).next();

  return {
    name: definition.name,
    role: definition.role,
    network: definition.network,
    ip: extractIp(latestDoc),
    status: toStatus(latestDoc, count > 0),
    icon: definition.icon,
    metrics: getLatestDocumentMetrics(definition.name, latestDoc),
    lastChecked: new Date().toISOString(),
  };
};

const getToolsStatus = async (req, res) => {
  try {
    const db = mongoose.connection.db;
    if (!db) {
      return res.status(503).json({ message: 'Database connection is not ready' });
    }

    const availableCollections = await db
      .listCollections({}, { nameOnly: true })
      .toArray()
      .then((list) => list.map((c) => c.name));
    const byLowerName = new Map(availableCollections.map((name) => [name.toLowerCase(), name]));

    const cards = await Promise.all(
      TOOL_DEFINITIONS.map(async (definition) => {
        const collectionName = byLowerName.get(definition.collection.toLowerCase());
        if (!collectionName) {
          return {
            name: definition.name,
            role: definition.role,
            network: definition.network,
            status: 'OFFLINE',
            icon: definition.icon,
            metrics: [
              { label: 'Documents', value: '0' },
              { label: 'Collection', value: definition.collection },
              { label: 'State', value: 'Missing' },
            ],
            lastChecked: new Date().toISOString(),
          };
        }

        return buildToolCard(db, definition, collectionName);
      })
    );

    return res.status(200).json(cards);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

module.exports = {
  getToolsStatus,
};
