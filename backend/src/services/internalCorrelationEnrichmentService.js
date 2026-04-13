const mongoose = require('mongoose');

const COLLECTION_CANDIDATES = {
  Cortex: 'cortex',
  MISP: 'misp',
  IRIS: 'iris',
  pfSense: 'pfsense',
};

const isPresent = (value) => {
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'boolean') return true;
  if (Array.isArray(value)) return value.some((entry) => isPresent(entry));
  if (value === null || value === undefined) return false;

  const text = String(value).trim();
  if (!text) return false;

  const lowered = text.toLowerCase();
  return !['nan', 'null', 'undefined', '-', 'none'].includes(lowered);
};

const toText = (value) => (isPresent(value) ? String(value).trim() : '');

const unique = (values) => Array.from(new Set(values.filter(Boolean)));

const safeNumber = (value) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

const mergeMissingFields = (base, patch) => {
  const next = { ...base };

  for (const [key, value] of Object.entries(patch || {})) {
    if (!isPresent(value)) continue;

    if (!isPresent(next[key])) {
      next[key] = value;
      continue;
    }

    if (Array.isArray(next[key]) && Array.isArray(value)) {
      next[key] = unique([...next[key], ...value]);
    }
  }

  return next;
};

const getDb = () => mongoose.connection.db;

let collectionMapCache = null;

const getCollectionMap = async () => {
  if (collectionMapCache) return collectionMapCache;

  const db = getDb();
  if (!db) return {};

  const collections = await db
    .listCollections({}, { nameOnly: true })
    .toArray()
    .then((items) => items.map((item) => item.name));

  const byLower = new Map(collections.map((name) => [name.toLowerCase(), name]));
  collectionMapCache = Object.fromEntries(
    Object.entries(COLLECTION_CANDIDATES)
      .map(([label, expected]) => [label, byLower.get(expected.toLowerCase()) || null])
  );

  return collectionMapCache;
};

const getIndicators = (alert) => unique([
  toText(alert.src_ip),
  toText(alert.target_ip),
  toText(alert.source_ref),
  toText(alert.iris_alert_source),
  toText(alert.fw_source_blocked),
  toText(alert.blocked_ip),
]);

const hasExistingInternalContext = (alert) => {
  const signals = [
    alert.misp,
    alert.misp_ioc,
    alert.misp_event_id,
    alert.iris_alert_id,
    alert.iris_uuid,
    alert.iris_status,
    alert.cortex_taxonomies,
    alert.vt_reputation,
    alert.vt_malicious,
    alert.fw_action_type,
    alert.pfsense_rule_id,
  ];

  return signals.some((signal) => isPresent(signal));
};

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const buildDescriptionRegex = (alert) => {
  const source = toText(alert.rule_description) || toText(alert.iris_alert_title);
  if (!source) return null;

  const tokens = source
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((token) => token.length >= 4)
    .slice(0, 6);

  if (tokens.length < 2) return null;
  return new RegExp(tokens.map(escapeRegex).join('.*'), 'i');
};

const findMatches = async (collectionName, query, limit = 5) => {
  if (!collectionName) return [];
  const db = getDb();
  if (!db) return [];
  return db.collection(collectionName).find(query).sort({ _id: -1 }).limit(limit).toArray();
};

const summarizeIds = (docs, field) => unique(docs.map((doc) => toText(doc[field]))).join(', ');

const enrichAlertWithInternalCorrelation = async (alertDoc) => {
  const baseAlert = typeof alertDoc.toObject === 'function' ? alertDoc.toObject() : { ...alertDoc };
  const db = getDb();
  if (!db) {
    return {
      ...baseAlert,
      internal_enrichment_status: 'internal-db-unavailable',
      internal_enrichment_checked: [],
      internal_enrichment_sources: [],
      internal_enrichment_summary: 'MongoDB connection is not ready for cross-tool enrichment.',
      internal_enrichment_indicator: '',
      internal_enrichment_fetched_at: '',
    };
  }

  const collectionMap = await getCollectionMap();
  const indicators = getIndicators(baseAlert);
  const descriptionRegex = buildDescriptionRegex(baseAlert);
  const checked = ['Cortex', 'MISP', 'IRIS', 'pfSense'].filter((label) => !!collectionMap[label]);

  if (!indicators.length && !descriptionRegex) {
    return {
      ...baseAlert,
      internal_enrichment_status: 'no-indicator',
      internal_enrichment_checked: checked,
      internal_enrichment_sources: [],
      internal_enrichment_summary: 'No IP or correlation signature is available for internal cross-tool enrichment.',
      internal_enrichment_indicator: '',
      internal_enrichment_fetched_at: '',
    };
  }

  const cortexMatches = indicators.length
    ? await findMatches(collectionMap.Cortex, { target_ip: { $in: indicators } })
    : [];
  const mispMatches = indicators.length
    ? await findMatches(collectionMap.MISP, { src_ip: { $in: indicators } })
    : [];
  const irisMatches = indicators.length
    ? await findMatches(collectionMap.IRIS, { source_ref: { $in: indicators } })
    : [];
  const pfSenseExactMatches = indicators.length
    ? await findMatches(collectionMap.pfSense, { blocked_ip: { $in: indicators } })
    : [];
  const pfSenseRelatedMatches =
    !pfSenseExactMatches.length && descriptionRegex
      ? await findMatches(collectionMap.pfSense, { rule_descr: descriptionRegex })
      : [];

  let mergedAlert = { ...baseAlert };
  const summaryParts = [];
  const sources = [];

  if (cortexMatches.length) {
    const latest = cortexMatches[0];
    mergedAlert = mergeMissingFields(mergedAlert, {
      vt_reputation: safeNumber(latest.vt_reputation),
      vt_malicious: safeNumber(latest.vt_malicious),
      target_ip: toText(latest.target_ip),
      cortex_job_id: toText(latest.job_id),
      cortex_status: toText(latest.status),
      is_private: toText(latest.is_private),
    });
    sources.push('Cortex');
    summaryParts.push(`Cortex job ${toText(latest.job_id) || 'n/a'} matched for ${toText(latest.target_ip) || indicators[0]}.`);
  }

  if (mispMatches.length) {
    mergedAlert = mergeMissingFields(mergedAlert, {
      misp: summarizeIds(mispMatches, 'event_id'),
      misp_event_id: summarizeIds(mispMatches, 'event_id'),
      misp_ioc: indicators[0],
      misp_error: toText(mispMatches[0].misp_error),
      misp_status: toText(mispMatches[0].status),
    });
    sources.push('MISP');
    summaryParts.push(`MISP events ${summarizeIds(mispMatches, 'event_id')} matched on ${indicators[0]}.`);
  }

  if (irisMatches.length) {
    mergedAlert = mergeMissingFields(mergedAlert, {
      iris_alert_id: summarizeIds(irisMatches, 'iris_alert_id'),
      iris_uuid: summarizeIds(irisMatches, 'iris_uuid'),
      iris_alert_source: toText(irisMatches[0].source_ref),
      iris_severity_name: toText(irisMatches[0].severity),
      iris_status: toText(irisMatches[0].iris_status),
    });
    sources.push('IRIS');
    summaryParts.push(`IRIS alerts ${summarizeIds(irisMatches, 'iris_alert_id')} matched on ${toText(irisMatches[0].source_ref) || indicators[0]}.`);
  }

  if (pfSenseExactMatches.length) {
    const latest = pfSenseExactMatches[0];
    mergedAlert = mergeMissingFields(mergedAlert, {
      pfsense_rule_id: summarizeIds(pfSenseExactMatches, 'pfsense_rule_id'),
      fw_action_type: 'block',
      fw_interface: toText(latest.interface),
      fw_source_blocked: toText(latest.blocked_ip),
      pfsense_status: toText(latest.status),
      pfsense_tracker: toText(latest.tracker),
    });
    sources.push('pfSense');
    summaryParts.push(`pfSense rules ${summarizeIds(pfSenseExactMatches, 'pfsense_rule_id')} matched blocked IP ${toText(latest.blocked_ip)}.`);
  } else if (pfSenseRelatedMatches.length) {
    sources.push('pfSense');
    summaryParts.push(`pfSense related containment rules ${summarizeIds(pfSenseRelatedMatches, 'pfsense_rule_id')} matched the same playbook pattern.`);
  }

  const hasSources = sources.length > 0;
  const status = hasSources
    ? 'internal-correlation'
    : hasExistingInternalContext(baseAlert)
      ? 'database-sufficient'
      : 'internal-unavailable';

  const fallbackSummary = hasExistingInternalContext(baseAlert)
    ? 'Stored alert data already includes internal SOC context, even if no extra cross-tool match was found.'
    : 'No internal cross-tool match was found in Cortex, MISP, IRIS, or pfSense.';

  return {
    ...mergedAlert,
    internal_enrichment_indicator: indicators[0] || '',
    internal_enrichment_status: status,
    internal_enrichment_sources: unique(sources),
    internal_enrichment_checked: checked,
    internal_enrichment_summary: summaryParts.join(' ') || fallbackSummary,
    internal_enrichment_fetched_at: new Date().toISOString(),
  };
};

module.exports = {
  enrichAlertWithInternalCorrelation,
};
