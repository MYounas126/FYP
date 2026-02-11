import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  Shield,
  TrendingUp,
  Clock,
  Zap,
  Wifi,
} from 'lucide-react'
import MonitoringPanel from '@/components/monitoring/MonitoringPanel'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import { dashboardApi } from '@/services/api'
import { format } from 'date-fns'
import { clsx } from 'clsx'
import type { AlertSeverity } from '@/types'

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
}

/**
 * Stat card component
 */
function StatCard({
  title,
  value,
  icon: Icon,
  trend,
  color = 'primary',
}: {
  title: string
  value: string | number
  icon: React.ElementType
  trend?: string
  color?: 'primary' | 'red' | 'green' | 'yellow'
}) {
  const colorClasses = {
    primary: 'bg-primary-500/20 text-primary-400',
    red: 'bg-red-500/20 text-red-400',
    green: 'bg-green-500/20 text-green-400',
    yellow: 'bg-yellow-500/20 text-yellow-400',
  }

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{title}</p>
          <p className="text-2xl font-bold text-white mt-1">{value}</p>
          {trend && (
            <p className="text-xs text-gray-500 mt-1 flex items-center">
              <TrendingUp className="h-3 w-3 mr-1" />
              {trend}
            </p>
          )}
        </div>
        <div className={clsx('p-3 rounded-lg', colorClasses[color])}>
          <Icon className="h-6 w-6" />
        </div>
      </div>
    </div>
  )
}

/**
 * Alert severity badge
 */
function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return (
    <span className={`badge badge-${severity}`}>
      {severity.toUpperCase()}
    </span>
  )
}

/**
 * Main dashboard page
 */
export default function DashboardPage() {
  // Fetch dashboard data
  const { data: overview, isLoading: loadingOverview } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: dashboardApi.getOverview,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: timeline, isLoading: loadingTimeline } = useQuery({
    queryKey: ['dashboard-timeline'],
    queryFn: () => dashboardApi.getTimeline(24),
    refetchInterval: 60000, // Refresh every minute
  })

  const { data: attackDist } = useQuery({
    queryKey: ['attack-distribution'],
    queryFn: dashboardApi.getAttackDistribution,
    refetchInterval: 60000,
  })

  if (loadingOverview) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
      </div>
    )
  }

  const stats = overview || {
    traffic: { total_flows_24h: 0, anomalies_24h: 0, anomaly_rate: 0, flows_last_hour: 0 },
    alerts: { total_24h: 0, critical: 0, high: 0, unresolved: 0 },
    recent_alerts: [],
    system: { status: 'unknown', last_updated: new Date().toISOString() },
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-400 mt-1">Real-time network security overview</p>
        </div>
        <div className="flex items-center text-sm text-gray-400">
          <Clock className="h-4 w-4 mr-2" />
          Last updated: {format(new Date(stats.system.last_updated), 'HH:mm:ss')}
        </div>
      </div>

      {/* Network Monitoring Panel */}
      <MonitoringPanel />

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Flows (24h)"
          value={stats.traffic.total_flows_24h.toLocaleString()}
          icon={Activity}
          trend={`${stats.traffic.flows_last_hour.toLocaleString()} last hour`}
          color="primary"
        />
        <StatCard
          title="Anomalies Detected"
          value={stats.traffic.anomalies_24h.toLocaleString()}
          icon={Zap}
          trend={`${stats.traffic.anomaly_rate}% of traffic`}
          color="yellow"
        />
        <StatCard
          title="Security Alerts"
          value={stats.alerts.total_24h}
          icon={AlertTriangle}
          trend={`${stats.alerts.unresolved} unresolved`}
          color="red"
        />
        <StatCard
          title="System Status"
          value={stats.system.status === 'healthy' ? 'Healthy' : 'Warning'}
          icon={Shield}
          color="green"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Traffic Timeline */}
        <div className="lg:col-span-2 card p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Traffic Timeline</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeline?.traffic || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="timestamp"
                  stroke="#64748b"
                  fontSize={12}
                  tickFormatter={(value) => format(new Date(value), 'HH:mm')}
                />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                  }}
                  labelFormatter={(value) => format(new Date(value), 'MMM d, HH:mm')}
                />
                <Line
                  type="monotone"
                  dataKey="flows"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={false}
                  name="Flows"
                />
                <Line
                  type="monotone"
                  dataKey="anomalies"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                  name="Anomalies"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Distribution */}
        <div className="card p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Attack Types</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={attackDist || []}
                  dataKey="count"
                  nameKey="category"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  label={({ category, percent }) =>
                    `${category} ${(percent * 100).toFixed(0)}%`
                  }
                  labelLine={false}
                >
                  {(attackDist || []).map((_, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={Object.values(SEVERITY_COLORS)[index % 4]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Alerts Table */}
      <div className="card">
        <div className="p-6 border-b border-dark-border">
          <h2 className="text-lg font-semibold text-white">Recent Alerts</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left text-sm text-gray-400 border-b border-dark-border">
                <th className="px-6 py-3">Time</th>
                <th className="px-6 py-3">Severity</th>
                <th className="px-6 py-3">Title</th>
                <th className="px-6 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {stats.recent_alerts.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-8 text-center text-gray-400">
                    No recent alerts
                  </td>
                </tr>
              ) : (
                stats.recent_alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="border-b border-dark-border hover:bg-dark-border/50 transition-colors"
                  >
                    <td className="px-6 py-4 text-sm text-gray-300">
                      {format(new Date(alert.timestamp), 'MMM d, HH:mm:ss')}
                    </td>
                    <td className="px-6 py-4">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-6 py-4 text-white">{alert.title}</td>
                    <td className="px-6 py-4 text-sm text-gray-400 capitalize">
                      {alert.status.replace('_', ' ')}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
