/**
 * TypeScript type definitions for SentinelFlow
 */

// =============================================================================
// User Types
// =============================================================================

export type UserRole = 'admin' | 'observer'

export interface User {
  id: string
  email: string
  username: string
  full_name: string | null
  role: UserRole
  is_active: boolean
  is_verified: boolean
  created_at: string
  updated_at: string
}

export interface LoginCredentials {
  username: string
  password: string
}

export interface AuthTokens {
  access_token: string
  refresh_token: string
  token_type: string
}

// =============================================================================
// Traffic Types
// =============================================================================

export interface NetworkTraffic {
  id: number
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number | null
  dst_port: number | null
  protocol: string | null
  bytes_sent: number
  bytes_received: number
  packets_sent: number
  packets_received: number
  duration: number
  flags: string | null
  flow_features: Record<string, unknown> | null
  is_anomaly: boolean
  anomaly_score: number | null
  attack_category: string | null
  mitre_tactic: string | null
  mitre_technique: string | null
  confidence: number | null
}

export interface TrafficStats {
  total_flows: number
  total_bytes: number
  total_packets: number
  anomaly_count: number
  anomaly_percentage: number
  top_sources: Array<{ ip: string; count: number }>
  top_destinations: Array<{ ip: string; count: number }>
  protocol_distribution: Record<string, number>
  attack_categories: Record<string, number>
  time_range: {
    start: string
    end: string
  }
}

// =============================================================================
// Alert Types
// =============================================================================

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'new' | 'investigating' | 'resolved' | 'false_positive'

export interface Alert {
  id: string
  timestamp: string
  severity: AlertSeverity
  title: string
  description: string | null
  src_ip: string | null
  dst_ip: string | null
  src_port: number | null
  dst_port: number | null
  attack_category: string | null
  mitre_tactic: string | null
  mitre_technique: string | null
  anomaly_score: number | null
  confidence: number | null
  traffic_id: number | null
  status: AlertStatus
  assigned_to: string | null
  resolved_at: string | null
  resolved_by: string | null
  notes: string | null
  created_at: string
  updated_at: string
}

export interface AlertStats {
  total_alerts: number
  new_alerts: number
  investigating_alerts: number
  resolved_alerts: number
  false_positives: number
  severity_distribution: Record<string, number>
  category_distribution: Record<string, number>
  hourly_trend: Array<{ hour: string; count: number }>
}

// =============================================================================
// Dashboard Types
// =============================================================================

export interface DashboardOverview {
  traffic: {
    total_flows_24h: number
    total_bytes_24h: number
    anomalies_24h: number
    flows_last_hour: number
    anomaly_rate: number
  }
  alerts: {
    total_24h: number
    critical: number
    high: number
    medium: number
    low: number
    unresolved: number
  }
  recent_alerts: Array<{
    id: string
    title: string
    severity: AlertSeverity
    timestamp: string
    status: AlertStatus
  }>
  system: {
    status: string
    last_updated: string
  }
}

export interface TimelineData {
  traffic: Array<{
    timestamp: string
    flows: number
    bytes: number
    anomalies: number
  }>
  alerts: Array<{
    timestamp: string
    critical: number
    high: number
    medium: number
    low: number
  }>
}

// =============================================================================
// WebSocket Types
// =============================================================================

export interface WSMessage {
  type: 'traffic' | 'alert' | 'connection' | 'system'
  data: unknown
  timestamp: string
}

export interface WSTrafficMessage extends WSMessage {
  type: 'traffic'
  data: NetworkTraffic
}

export interface WSAlertMessage extends WSMessage {
  type: 'alert'
  data: Alert
}

// =============================================================================
// API Types
// =============================================================================

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface ApiError {
  detail: string
}

export interface QueryParams {
  limit?: number
  offset?: number
  start_time?: string
  end_time?: string
}

export interface TrafficQueryParams extends QueryParams {
  src_ip?: string
  dst_ip?: string
  protocol?: string
  is_anomaly?: boolean
  attack_category?: string
  min_anomaly_score?: number
}

export interface AlertQueryParams extends QueryParams {
  severity?: AlertSeverity
  status?: AlertStatus
  attack_category?: string
  assigned_to?: string
}
