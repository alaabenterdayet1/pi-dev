const dns = require('node:dns').promises;

const ENRICHMENT_CACHE_TTL_MS = Math.max(
  60_000,
  Number(process.env.EXTERNAL_ENRICHMENT_CACHE_TTL_MS || 15 * 60 * 1000)
);
const ENRICHMENT_TIMEOUT_MS = Math.max(
  1_000,
  Number(process.env.EXTERNAL_ENRICHMENT_TIMEOUT_MS || 4_000)
);
const DEFAULT_GEOIP_URL = 'https://ipwho.is/{indicator}';

const enrichmentCache = new Map();

const toPlainObject = (value) => {
  if (!value) return {};
  return typeof value.toObject === 'function' ? value.toObject() : { ...value };
};

const isPresent = (value) => {
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.some((entry) => isPresent(entry));
  if (typeof value === 'boolean') return true;
  if (value === null || value === undefined) return false;

  const text = String(value).trim();
  if (!text) return false;

  const lowered = text.toLowerCase();
  return !['nan', 'null', 'undefined', '-', 'none'].includes(lowered);
};

const pickFirstPresent = (values) => values.find((value) => isPresent(value));

const safeNumber = (value) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

const joinParts = (parts) => parts.filter((part) => isPresent(part)).join(' | ');

const isIpv4 = (value) => /^(\d{1,3}\.){3}\d{1,3}$/.test(String(value || '').trim());

const isPrivateIpv4 = (value) => {
  if (!isIpv4(value)) return false;
  const [a, b] = String(value).split('.').map(Number);
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
};

const cacheKeyForIndicator = (indicator) => String(indicator || '').trim().toLowerCase();

const getCachedEnrichment = (indicator) => {
  const cacheKey = cacheKeyForIndicator(indicator);
  const cached = enrichmentCache.get(cacheKey);
  if (!cached) return null;
  if (cached.expiresAt <= Date.now()) {
    enrichmentCache.delete(cacheKey);
    return null;
  }
  return cached.payload;
};

const setCachedEnrichment = (indicator, payload) => {
  const cacheKey = cacheKeyForIndicator(indicator);
  enrichmentCache.set(cacheKey, {
    payload,
    expiresAt: Date.now() + ENRICHMENT_CACHE_TTL_MS,
  });
};

const withTimeout = async (promiseFactory) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ENRICHMENT_TIMEOUT_MS);

  try {
    return await promiseFactory(controller.signal);
  } finally {
    clearTimeout(timeout);
  }
};

const fetchJson = async (url, options = {}) => {
  const response = await withTimeout((signal) => fetch(url, { ...options, signal }));
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for ${url}`);
  }
  return response.json();
};

const resolveIndicator = (alert) => {
  const indicator = pickFirstPresent([
    alert.src_ip,
    alert.source_ip,
    alert.target_ip,
    alert.targetIp,
  ]);

  return isPresent(indicator) ? String(indicator).trim() : '';
};

const hasMissingThreatContext = (alert) => {
  const requiredSignals = [
    alert.vt_reputation,
    alert.vt_malicious,
    alert.vt_suspicious,
    alert.vt_undetected,
    alert.vt_tags,
    alert.geo_ip,
    alert.geoip_country,
    alert.rdns,
    alert.abuseipdb_score,
  ];

  return requiredSignals.some((signal) => !isPresent(signal));
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
      next[key] = Array.from(new Set([...next[key], ...value]));
    }
  }

  return next;
};

const buildMetadata = (baseAlert, indicator, payload, override = {}) => {
  const existingSources = Array.isArray(baseAlert.external_enrichment_sources)
    ? baseAlert.external_enrichment_sources
    : [];
  const payloadSources = Array.isArray(payload?.sources) ? payload.sources : [];
  const sources = Array.from(new Set([...existingSources, ...payloadSources]));

  return {
    external_enrichment_indicator: indicator || baseAlert.external_enrichment_indicator || '',
    external_enrichment_status:
      override.status || payload?.status || baseAlert.external_enrichment_status || 'database-only',
    external_enrichment_sources: sources,
    external_enrichment_checked:
      override.checked || payload?.checked || baseAlert.external_enrichment_checked || [],
    external_enrichment_summary:
      override.summary || payload?.summary || baseAlert.external_enrichment_summary || '',
    external_enrichment_fetched_at:
      override.fetchedAt || payload?.fetchedAt || baseAlert.external_enrichment_fetched_at || '',
    external_enrichment_cache_hit:
      override.cacheHit ?? payload?.cacheHit ?? baseAlert.external_enrichment_cache_hit ?? false,
  };
};

const fetchVirusTotalIp = async (indicator) => {
  const apiKey = String(process.env.VIRUSTOTAL_API_KEY || '').trim();
  if (!apiKey || !isIpv4(indicator) || isPrivateIpv4(indicator)) return null;

  const data = await fetchJson(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`, {
    headers: {
      'x-apikey': apiKey,
      accept: 'application/json',
    },
  });

  const attributes = data?.data?.attributes || {};
  const stats = attributes.last_analysis_stats || {};
  const tags = Array.isArray(attributes.tags) ? attributes.tags : [];

  return {
    source: 'VirusTotal',
    fields: {
      vt_reputation: safeNumber(attributes.reputation),
      vt_malicious: safeNumber(stats.malicious),
      vt_suspicious: safeNumber(stats.suspicious),
      vt_undetected: safeNumber(stats.undetected),
      vt_tags: tags.length ? tags.join(', ') : undefined,
      vt_as_owner: attributes.as_owner || undefined,
      geoip_country: attributes.country || undefined,
    },
    summary: joinParts([
      `VT reputation=${safeNumber(attributes.reputation) ?? 'n/a'}`,
      `malicious=${safeNumber(stats.malicious) ?? 'n/a'}`,
      `suspicious=${safeNumber(stats.suspicious) ?? 'n/a'}`,
      tags.length ? `tags=${tags.slice(0, 5).join(', ')}` : '',
    ]),
  };
};

const fetchAbuseIpDb = async (indicator) => {
  const apiKey = String(process.env.ABUSEIPDB_API_KEY || '').trim();
  if (!apiKey || !isIpv4(indicator) || isPrivateIpv4(indicator)) return null;

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90&verbose=true`;
  const data = await fetchJson(url, {
    headers: {
      Key: apiKey,
      accept: 'application/json',
    },
  });

  const payload = data?.data || {};
  return {
    source: 'AbuseIPDB',
    fields: {
      abuseipdb_score: safeNumber(payload.abuseConfidenceScore),
      abuseipdb_total_reports: safeNumber(payload.totalReports),
      abuseipdb_last_reported_at: payload.lastReportedAt || undefined,
      geoip_country: payload.countryCode || undefined,
      rdns: payload.domain || undefined,
    },
    summary: joinParts([
      `abuse score=${safeNumber(payload.abuseConfidenceScore) ?? 'n/a'}`,
      `reports=${safeNumber(payload.totalReports) ?? 'n/a'}`,
      payload.usageType || '',
      payload.isp || '',
    ]),
  };
};

const fetchGeoIpContext = async (indicator) => {
  if (!isIpv4(indicator) || isPrivateIpv4(indicator)) return null;

  const template = String(process.env.GEOIP_LOOKUP_URL || DEFAULT_GEOIP_URL).trim();
  if (!template) return null;

  const url = template.replace('{indicator}', encodeURIComponent(indicator));
  const data = await fetchJson(url, { headers: { accept: 'application/json' } });

  if (data?.success === false) return null;

  return {
    source: 'GeoIP',
    fields: {
      geo_ip: joinParts([data.city, data.country, data.continent]),
      geoip_country: data.country_code || data.country || undefined,
    },
    summary: joinParts([
      data.type || '',
      data.city || '',
      data.country || '',
      data?.connection?.isp || '',
    ]),
  };
};

const fetchReverseDns = async (indicator) => {
  if (!isIpv4(indicator)) return null;

  try {
    const hostnames = await dns.reverse(indicator);
    if (!Array.isArray(hostnames) || !hostnames.length) return null;

    return {
      source: 'Reverse DNS',
      fields: {
        rdns: hostnames.slice(0, 3).join(', '),
      },
      summary: `rdns=${hostnames.slice(0, 3).join(', ')}`,
    };
  } catch (_error) {
    return null;
  }
};

const fetchExternalThreatContext = async (indicator) => {
  const checked = [];
  const unavailable = [];
  const virustotalConfigured = !!String(process.env.VIRUSTOTAL_API_KEY || '').trim();
  const abuseConfigured = !!String(process.env.ABUSEIPDB_API_KEY || '').trim();

  const tasks = [
    { label: 'VirusTotal', run: () => fetchVirusTotalIp(indicator) },
    { label: 'AbuseIPDB', run: () => fetchAbuseIpDb(indicator) },
    { label: 'GeoIP', run: () => fetchGeoIpContext(indicator) },
    { label: 'Reverse DNS', run: () => fetchReverseDns(indicator) },
  ];

  const results = await Promise.allSettled(
    tasks.map(async (task) => {
      checked.push(task.label);
      if (task.label === 'VirusTotal' && !virustotalConfigured) {
        unavailable.push('VirusTotal API key missing');
      }
      if (task.label === 'AbuseIPDB' && !abuseConfigured) {
        unavailable.push('AbuseIPDB API key missing');
      }
      return task.run();
    })
  );

  const successful = results
    .filter((result) => result.status === 'fulfilled' && result.value)
    .map((result) => result.value);

  const patch = successful.reduce((acc, result) => mergeMissingFields(acc, result.fields), {});
  const sources = successful
    .filter((result) => Object.keys(result.fields || {}).some((key) => isPresent(patch[key])))
    .map((result) => result.source);
  const summary = successful.map((result) => result.summary).filter(Boolean).join(' | ');
  const fallbackSummary = [
    sources.length ? '' : 'No external provider returned usable threat context.',
    unavailable.length ? `Configuration: ${Array.from(new Set(unavailable)).join(' | ')}.` : '',
    !sources.length && !unavailable.length ? 'Indicator may be unsupported or the providers returned no data.' : '',
  ].filter(Boolean).join(' ');

  return {
    fields: patch,
    sources,
    checked,
    summary: summary || fallbackSummary,
    fetchedAt: new Date().toISOString(),
    status: sources.length ? 'external-fallback' : 'external-unavailable',
    cacheHit: false,
  };
};

const enrichAlertWithExternalContext = async (alertDoc, options = {}) => {
  const baseAlert = toPlainObject(alertDoc);
  const indicator = resolveIndicator(baseAlert);

  if (!indicator) {
    return {
      ...baseAlert,
      ...buildMetadata(baseAlert, '', null, {
        status: 'no-indicator',
        summary: 'No source IP or supported indicator is available for external enrichment.',
      }),
    };
  }

  if (!options.force && !hasMissingThreatContext(baseAlert)) {
    return {
      ...baseAlert,
      ...buildMetadata(baseAlert, indicator, null, {
        status: 'database-sufficient',
        summary: 'Threat context is already available from stored alert data.',
      }),
    };
  }

  const cached = getCachedEnrichment(indicator);
  if (cached) {
    return {
      ...mergeMissingFields(baseAlert, cached.fields),
      ...buildMetadata(baseAlert, indicator, cached, {
        status: cached.status || 'external-cache',
        cacheHit: true,
      }),
    };
  }

  if (isPrivateIpv4(indicator)) {
    return {
      ...baseAlert,
      ...buildMetadata(baseAlert, indicator, null, {
        status: 'private-indicator',
        summary: 'The source IP is private/local, so public reputation feeds were skipped.',
      }),
    };
  }

  const payload = await fetchExternalThreatContext(indicator);
  setCachedEnrichment(indicator, payload);

  return {
    ...mergeMissingFields(baseAlert, payload.fields),
    ...buildMetadata(baseAlert, indicator, payload),
  };
};

module.exports = {
  enrichAlertWithExternalContext,
};
