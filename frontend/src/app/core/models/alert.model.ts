export interface AlertItem {
  _id?: string | { $oid?: string };
  rule_id?: string;
  rule_level?: number;
  rule_description?: string;
  fired_times?: number;
  rule_groups?: string;
  mitre_ids?: string;
  mitre_tactics?: string;
  mitre_techniques?: string;
  agent_name?: string;
  src_ip?: string;
  src_port?: string;
  dst_user?: string;
  user?: string;
  username?: string;
  dstuser?: string;
  log_program?: string;
  log_location?: string;
  decoder_name?: string;
  vt_reputation?: number;
  vt_malicious?: number;
  vt_suspicious?: number;
  vt_undetected?: number;
  vt_tags?: string;
  cortex_taxonomies?: string;
  iris_severity_id?: number;
  iris_severity_name?: string;
  iris_alert_title?: string;
  iris_alert_source?: string;
  fw_action_type?: string;
  fw_interface?: string;
  fw_source_blocked?: string;
  date?: string;
  detected?: string;
  detected_at?: string;
  timestamp?: string;
  created_at?: string;
  failed_attempts?: number;
  failed_logins?: number;
  auth_failures?: number;
  geo_ip?: string;
  geoip?: string;
  geoip_country?: string;
  misp?: string;
  misp_ioc?: string;
  misp_event_id?: string;
  alert_status_updated_at?: string;
  alert_status_history?: Array<{ status?: string; changed_at?: string }>;
  alert_status?: 'OPEN' | 'INVESTIGATING' | 'CLOSED';

  severity?: string;
  confidence?: number | string;

  ai_classification?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  ai_decision?: 'ISOLATE' | 'ESCALATE' | 'INVESTIGATE' | 'MONITOR';
  ai_confidence?: number;
  ai_score?: number;
  ai_risk_score?: number;
  ai_recommendation?: string;
  mttd_minutes?: number;
  mttr_minutes?: number;
}

export interface AlertsResponse {
  count: number;
  data: AlertItem[];
}
