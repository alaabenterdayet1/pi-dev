import { PipelineSummary } from '../models/ai-score.model';
import { AlertItem } from '../models/alert.model';
import { Incident } from '../models/incident.model';
import { ToolStatus } from '../models/tool-status.model';
import { getAlertMttd, getAlertMttr } from './alert-metrics.util';

export interface ValidationInsightItem {
  label: string;
  value: string;
  tone?: 'neutral' | 'accent' | 'success' | 'warning';
}

export interface ValidationInsightSection {
  title: string;
  subtitle: string;
  items: ValidationInsightItem[];
}

const SHORT_HEALTHCARE_CONTEXT = 'Healthcare SOC | EHR | identities | workstations | IoMT';
const SHORT_ANALYST_OVERRIDE = 'Status | escalate | isolate | monitor';

const toText = (value: unknown): string => {
  if (value === undefined || value === null) return '';
  const text = String(value).trim();
  const lowered = text.toLowerCase();
  if (!text || lowered === 'nan' || lowered === 'null' || lowered === 'undefined' || lowered === '-') {
    return '';
  }
  return text;
};

const toNumber = (value: unknown): number | null => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};

const shortenText = (value: string, max = 68): string => {
  const text = toText(value).replace(/\s+/g, ' ').trim();
  if (!text) return '';
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1).trim()}…`;
};

const splitValueList = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return Array.from(new Set(value.map((entry) => toText(entry)).filter(Boolean)));
  }

  const text = toText(value);
  if (!text) return [];

  return Array.from(new Set(text.split(',').map((entry) => entry.trim()).filter(Boolean)));
};

const countValueItems = (value: unknown): number => splitValueList(value).length;

const joinReadable = (values: Array<string | undefined>, fallback: string): string => {
  const unique = Array.from(new Set(values.map((value) => toText(value)).filter(Boolean)));
  return unique.length ? unique.join(' | ') : fallback;
};

const normalizeDecision = (value: string, score: number): string => {
  const decision = toText(value).toUpperCase();
  if (decision === 'ISOLATE' || decision === 'ESCALATE' || decision === 'INVESTIGATE' || decision === 'MONITOR') {
    return decision;
  }
  if (score >= 85) return 'ISOLATE';
  if (score >= 65) return 'ESCALATE';
  if (score >= 40) return 'INVESTIGATE';
  return 'MONITOR';
};

const scoreToPriority = (score: number): string => {
  if (score >= 85) return 'P1';
  if (score >= 65) return 'P2';
  if (score >= 40) return 'P3';
  return 'P4';
};

const inferUseCase = (values: Array<string | undefined>): string => {
  const haystack = values.map((value) => toText(value).toLowerCase()).join(' ');

  if (haystack.includes('powershell')) return 'PowerShell execution';
  if (haystack.includes('sudo') || haystack.includes('privilege')) {
    return 'Privilege escalation';
  }
  if (haystack.includes('ransom') || haystack.includes('malware')) {
    return 'Malware / ransomware';
  }
  if (haystack.includes('exfil') || haystack.includes('outbound')) {
    return 'Data exfiltration';
  }
  if (haystack.includes('scan') || haystack.includes('recon')) {
    return 'Recon / scanning';
  }
  if (haystack.includes('login') || haystack.includes('auth') || haystack.includes('credential') || haystack.includes('sshd')) {
    return 'Auth failure / credential misuse';
  }

  return 'SOC triage on sensitive assets';
};

const getMitreSummary = (record: Record<string, unknown>): string => {
  return shortenText(joinReadable(
    [
      toText(record['mitre_ids']),
      toText(record['mitre_tactics']),
      toText(record['mitre_techniques']),
    ],
    'MITRE mapping missing.'
  ), 64);
};

const compactSourceLabel = (value: string): string => {
  const normalized = value.toLowerCase();
  if (normalized.includes('wazuh')) return 'Wazuh';
  if (normalized.includes('misp')) return 'MISP';
  if (normalized.includes('cortex')) return 'Cortex';
  if (normalized.includes('iris')) return 'IRIS';
  if (normalized.includes('pfsense')) return 'pfSense';
  if (normalized.includes('virus')) return 'VirusTotal';
  if (normalized.includes('abuse')) return 'AbuseIPDB';
  return value;
};

const getThreatSources = (record: Record<string, unknown>): string[] => {
  const sources: string[] = [];
  const enrichmentSourceValue =
    record['enrichment_sources'] ??
    record['internal_enrichment_sources'] ??
    record['external_enrichment_sources'];
  const externalSources = Array.isArray(enrichmentSourceValue)
    ? enrichmentSourceValue.map((value) => toText(value)).filter(Boolean)
    : toText(enrichmentSourceValue)
      ? [toText(enrichmentSourceValue)]
      : [];

  if (toText(record['rule_id']) || toText(record['agent_name']) || toText(record['decoder_name'])) {
    sources.push('Wazuh / internal telemetry');
  }
  if (toText(record['misp']) || toText(record['misp_ioc']) || toText(record['misp_event_id'])) {
    sources.push('MISP feed');
  }
  if (
    toText(record['vt_reputation']) ||
    toText(record['vt_malicious']) ||
    toText(record['vt_suspicious']) ||
    toText(record['cortex_taxonomies'])
  ) {
    sources.push('Cortex / VT enrichment');
  }
  if (toText(record['iris_alert_id']) || toText(record['iris_uuid']) || toText(record['iris_alert_source'])) {
    sources.push('IRIS case context');
  }
  if (toText(record['fw_action_type']) || toText(record['pfsense_rule_id']) || toText(record['blocked_ip'])) {
    sources.push('pfSense enforcement');
  }
  if (externalSources.length) {
    sources.push(...externalSources);
  }

  return Array.from(new Set((sources.length ? sources : ['Internal SOC telemetry']).map(compactSourceLabel)));
};

const buildWorkflowSummary = (record: Record<string, unknown>, decision: string): string => {
  const hasDetection = toText(record['rule_id']) || toText(record['agent_name']);
  const hasEnrichment =
    toText(record['misp']) ||
    toText(record['misp_ioc']) ||
    toText(record['misp_event_id']) ||
    toText(record['vt_malicious']) ||
    toText(record['vt_suspicious']) ||
    toText(record['cortex_taxonomies']);
  const hasCase = toText(record['iris_alert_id']) || toText(record['iris_uuid']) || toText(record['iris_alert_source']);
  const hasContainment =
    toText(record['fw_action_type']).toLowerCase() === 'block' ||
    !!toText(record['pfsense_rule_id']) ||
    decision === 'ISOLATE';

  const steps = [
    hasDetection ? 'Wazuh' : 'Telemetry',
    hasEnrichment ? 'CTI' : 'No CTI',
    hasCase ? 'IRIS' : 'No case',
    hasContainment ? decision : 'Review',
  ];

  return steps.join(' -> ');
};

const buildPlaybookSummary = (decision: string, action: string): string => {
  if (decision === 'ISOLATE' || action === 'block') {
    return 'Containment + escalation';
  }
  if (decision === 'ESCALATE') {
    return 'Tier-2 escalation';
  }
  if (decision === 'INVESTIGATE') {
    return 'Guided investigation';
  }
  return 'Monitor + analyst review';
};

const buildTuningSummary = (ruleLevel: number, firedTimes: number, action: string): string => {
  return `rule ${ruleLevel} | fired ${firedTimes} | fw ${action || 'n/a'}`;
};

const buildExplainabilitySummary = (
  score: number,
  confidence: number,
  ruleLevel: number,
  firedTimes: number,
  malicious: number,
  suspicious: number
): string => {
  return `score ${score} | conf ${confidence}% | rule ${ruleLevel} | fired ${firedTimes} | VT ${malicious}/${suspicious}`;
};

const buildLimitSummary = (values: Array<string | undefined>, fallback: string): string => {
  const limits = values.map((value) => toText(value)).filter(Boolean);
  return shortenText(limits[0] || fallback, 72);
};

const buildImpactSummary = (
  score: number,
  confidence: number,
  mttd: number,
  mttr: number,
  pipelineSummary?: PipelineSummary | null
): string => {
  const summaryParts = [`MTTD ${mttd}m`, `MTTR ${mttr}m`, `${confidence}%`, scoreToPriority(score)];
  if (pipelineSummary) {
    summaryParts.push(`avg ${pipelineSummary.statistics.avgAiScore.toFixed(1)}`);
  }
  return summaryParts.join(' | ');
};

const buildFeedSummary = (record: Record<string, unknown>): string => {
  return getThreatSources(record).slice(0, 5).join(' | ');
};

const buildCorrelationSummary = (record: Record<string, unknown>): string => {
  const parts: string[] = [];

  const mispCount = countValueItems(record['misp_event_id'] || record['misp']);
  const irisCount = countValueItems(record['iris_alert_id']);
  const pfSenseCount = countValueItems(record['pfsense_rule_id']);
  const cortexHits = countValueItems(record['cortex_job_id']);

  if (mispCount) parts.push(`MISP ${mispCount}`);
  if (irisCount) parts.push(`IRIS ${irisCount}`);
  if (pfSenseCount) parts.push(`pfSense ${pfSenseCount}`);
  else if (getThreatSources(record).includes('pfSense')) parts.push('pfSense linked');
  if (cortexHits) parts.push(`Cortex ${cortexHits}`);

  const vtTags = toText(record['vt_tags']);
  if (vtTags) parts.push(`VT ${shortenText(vtTags, 20)}`);

  const geo = toText(record['geoip_country']) || toText(record['geo_ip']);
  if (geo) parts.push(shortenText(geo, 18));

  const enrichmentStatus = toText(record['enrichment_status']) || toText(record['internal_enrichment_status']) || toText(record['external_enrichment_status']);
  if (enrichmentStatus === 'private-indicator') parts.push('Private IP');
  if (enrichmentStatus === 'external-unavailable') parts.push('No public feed');
  if (enrichmentStatus === 'internal-unavailable') parts.push('No internal match');

  return parts.join(' | ') || 'No cross-tool context';
};

const buildInputSummary = (source: Record<string, unknown>, asset: string): string => {
  return joinReadable(
    [
      shortenText(asset, 18),
      shortenText(toText(source['rule_description']) || toText(source['iris_alert_title']), 28),
      toText(source['rule_level']) && `rule ${toText(source['rule_level'])}`,
      toText(source['fired_times']) && `x${toText(source['fired_times'])}`,
      toText(source['mitre_ids']) && shortenText(toText(source['mitre_ids']), 18),
    ],
    'Rule / severity / CTI inputs'
  );
};

const buildIncidentSections = (
  source: Record<string, unknown>,
  options: {
    asset: string;
    score: number;
    confidence: number;
    decision: string;
    mttd: number;
    mttr: number;
    status: string;
    limitations: string[];
    typeValues: Array<string | undefined>;
    pipelineSummary?: PipelineSummary | null;
  }
): ValidationInsightSection[] => {
  const ruleLevel = toNumber(source['rule_level']) ?? 0;
  const firedTimes = toNumber(source['fired_times']) ?? 0;
  const malicious = toNumber(source['vt_malicious']) ?? 0;
  const suspicious = toNumber(source['vt_suspicious']) ?? 0;
  const action = toText(source['fw_action_type']) || 'monitor';
  const threatSources = getThreatSources(source);
  const useCase = inferUseCase(options.typeValues);
  const hasAuditTrail =
    (Array.isArray(source['alert_status_history']) && source['alert_status_history'].length > 0) ||
    !!toText(source['alert_status_updated_at']) ||
    options.status === 'CLOSED' ||
    options.status === 'INVESTIGATING';

  return [
    {
      title: 'IR Core Alignment',
      subtitle: '',
      items: [
        { label: 'Sector Context', value: SHORT_HEALTHCARE_CONTEXT, tone: 'accent' },
        { label: 'Priority Use Case', value: useCase },
        { label: 'Playbook', value: buildPlaybookSummary(options.decision, action) },
        { label: 'SOC Workflow', value: buildWorkflowSummary(source, options.decision) },
        {
          label: 'KPI / Testing',
          value: buildImpactSummary(options.score, options.confidence, options.mttd, options.mttr, options.pipelineSummary),
          tone: 'success',
        },
        {
          label: 'Compliance / Audit',
          value: hasAuditTrail
            ? 'Status history + analyst actions'
            : 'Audit trail partial',
          tone: hasAuditTrail ? 'success' : 'warning',
        },
      ],
    },
    {
      title: 'CTI Core Alignment',
      subtitle: '',
      items: [
        {
          label: 'Feed Strategy',
          value: buildFeedSummary(source),
          tone: 'accent',
        },
        {
          label: 'Correlation / Enrichment',
          value: buildCorrelationSummary(source),
        },
        { label: 'MITRE / Sector Relevance', value: getMitreSummary(source) },
        {
          label: 'Operational Prioritization',
          value: `${options.decision} | score ${options.score} | ${scoreToPriority(options.score)}`,
          tone: 'success',
        },
        { label: 'Technical Tuning', value: buildTuningSummary(ruleLevel, firedTimes, action) },
      ],
    },
    {
      title: 'AI / ML Governance',
      subtitle: '',
      items: [
        {
          label: 'Inputs',
          value: buildInputSummary(source, options.asset),
        },
        {
          label: 'Outputs',
          value: `${options.score} | ${options.decision} | ${options.confidence}% | ${options.status}`,
          tone: 'accent',
        },
        {
          label: 'Explainability',
          value: buildExplainabilitySummary(
            options.score,
            options.confidence,
            ruleLevel,
            firedTimes,
            malicious,
            suspicious
          ),
        },
        { label: 'Analyst Override', value: SHORT_ANALYST_OVERRIDE, tone: 'success' },
        {
          label: 'Limits / Risks',
          value: buildLimitSummary(
            options.limitations,
            'Dataset sparsity, false positives, and missing context remain the main operational risks.'
          ),
          tone: 'warning',
        },
      ],
    },
  ];
};

export const buildAlertValidationSections = (
  alert: AlertItem,
  pipelineSummary?: PipelineSummary | null
): ValidationInsightSection[] => {
  const source = alert as unknown as Record<string, unknown>;
  const score = Math.round(
    Math.max(
      0,
      Math.min(100, toNumber(source['ai_score']) ?? toNumber(source['ai_risk_score']) ?? 0)
    )
  );
  const confidence = Math.round(
    Math.max(0, Math.min(100, toNumber(source['ai_confidence']) ?? toNumber(source['confidence']) ?? 0))
  );
  const decision = normalizeDecision(toText(source['ai_decision']), score);
  const limitations = [
    !toText(source['rule_level']) ? 'Missing rule level weakens prioritization confidence.' : '',
    !toText(source['fired_times']) ? 'Fired-times context is missing for behavior recurrence analysis.' : '',
    !toText(source['src_ip']) ? 'Source IP is absent, limiting attribution and CTI correlation.' : '',
    !toText(source['vt_malicious']) && !toText(source['vt_suspicious'])
      ? 'Threat-intelligence enrichment is incomplete for this alert.'
      : '',
  ].filter(Boolean);

  return buildIncidentSections(source, {
    asset: joinReadable(
      [toText(source['agent_name']), toText(source['src_ip']), toText(source['dst_user'])],
      'Sensitive healthcare asset'
    ),
    score,
    confidence,
    decision,
    mttd: getAlertMttd(alert),
    mttr: getAlertMttr(alert),
    status: toText(source['alert_status']).toUpperCase() || 'OPEN',
    limitations,
    typeValues: [toText(source['rule_description']), toText(source['iris_alert_title']), toText(source['decoder_name'])],
    pipelineSummary,
  });
};

export const buildIncidentValidationSections = (
  incident: Incident,
  pipelineSummary?: PipelineSummary | null
): ValidationInsightSection[] => {
  const source = incident.rawDetails ?? {};
  const limitations = [
    !toText(source['rule_level']) ? 'Missing rule level weakens prioritization confidence.' : '',
    !toText(source['fired_times']) ? 'Fired-times context is missing for behavior recurrence analysis.' : '',
    !toText(source['src_ip']) ? 'Source IP is absent, limiting attribution and CTI correlation.' : '',
    !toText(source['vt_malicious']) && !toText(source['vt_suspicious'])
      ? 'Threat-intelligence enrichment is incomplete for this alert.'
      : '',
  ].filter(Boolean);

  return buildIncidentSections(source, {
    asset: incident.asset,
    score: incident.aiScore,
    confidence: incident.confidence,
    decision: normalizeDecision(incident.decision, incident.aiScore),
    mttd: incident.mttd,
    mttr: incident.mttr,
    status: incident.status,
    limitations,
    typeValues: [incident.type, toText(source['rule_description']), toText(source['iris_alert_title'])],
    pipelineSummary,
  });
};

export const buildToolValidationSections = (tools: ToolStatus[]): ValidationInsightSection[] => {
  const online = tools.filter((tool) => tool.status === 'ONLINE').length;
  const visibleNames = tools.map((tool) => tool.name);

  const detection = visibleNames.filter((name) => /wazuh/i.test(name)).join(' | ') || 'Wazuh';
  const enrichment = visibleNames.filter((name) => /misp|cortex/i.test(name)).join(' | ') || 'MISP | Cortex';
  const caseMgmt = visibleNames.filter((name) => /iris/i.test(name)).join(' | ') || 'IRIS';
  const enforcement = visibleNames.filter((name) => /pfsense/i.test(name)).join(' | ') || 'pfSense';

  return [
    {
      title: 'Validation Coverage',
      subtitle: '',
      items: [
        { label: 'Sector Context', value: SHORT_HEALTHCARE_CONTEXT, tone: 'accent' },
        {
          label: 'Priority Use Cases',
          value: 'Credential misuse | privilege escalation | malware | IOC triage',
        },
        {
          label: 'Workflow Chain',
          value: `${detection} -> ${enrichment} -> ${caseMgmt} -> ${enforcement}`,
          tone: 'success',
        },
        {
          label: 'Operational Coverage',
          value: `${online}/${tools.length || 1} tools online`,
          tone: online >= Math.max(1, Math.ceil(tools.length / 2)) ? 'success' : 'warning',
        },
      ],
    },
    {
      title: 'Governance and KPI',
      subtitle: '',
      items: [
        {
          label: 'KPI Visibility',
          value: 'MTTD | MTTR | automation | FPR | prioritization',
        },
        {
          label: 'Compliance / Auditability',
          value: 'Case history + tool traceability',
        },
        {
          label: 'Tuning / Flexibility',
          value: 'Rules | thresholds | feeds | workflows',
        },
      ],
    },
  ];
};

export const getToolValidationRole = (toolName: string): string => {
  const normalized = toolName.trim().toLowerCase();
  if (normalized.includes('misp')) return 'Threat feeds and IOC sharing';
  if (normalized.includes('cortex')) return 'Enrichment and analyzer context';
  if (normalized.includes('wazuh agent')) return 'Endpoint telemetry collection';
  if (normalized.includes('wazuh')) return 'Detection and SIEM correlation';
  if (normalized.includes('iris')) return 'Case management and audit trail';
  if (normalized.includes('pfsense')) return 'Containment and enforcement';
  if (normalized.includes('n8n')) return 'SOAR orchestration';
  return 'SOC integration role';
};

export const getToolWorkflowStage = (toolName: string): string => {
  const normalized = toolName.trim().toLowerCase();
  if (normalized.includes('misp')) return 'Feed ingest';
  if (normalized.includes('cortex')) return 'Enrichment';
  if (normalized.includes('wazuh agent')) return 'Endpoint collect';
  if (normalized.includes('wazuh')) return 'Detect / correlate';
  if (normalized.includes('iris')) return 'Case / decision';
  if (normalized.includes('pfsense')) return 'Contain / block';
  if (normalized.includes('n8n')) return 'Automate';
  return 'SOC flow';
};
