import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Filter, ChevronDown } from 'lucide-react'
import { format } from 'date-fns'
import { alertsApi } from '@/services/api'
import { clsx } from 'clsx'
import type { AlertSeverity, AlertStatus } from '@/types'

const SEVERITY_OPTIONS: AlertSeverity[] = ['critical', 'high', 'medium', 'low']
const STATUS_OPTIONS: AlertStatus[] = ['new', 'investigating', 'resolved', 'false_positive']

/**
 * Alerts page with filtering and details
 */
export default function AlertsPage() {
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | ''>('')
  const [statusFilter, setStatusFilter] = useState<AlertStatus | ''>('')
  const [searchTerm, setSearchTerm] = useState('')

  const { data: alerts, isLoading } = useQuery({
    queryKey: ['alerts', severityFilter, statusFilter],
    queryFn: () =>
      alertsApi.list({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        limit: 100,
      }),
    refetchInterval: 30000,
  })

  const { data: stats } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => alertsApi.getStats(),
    refetchInterval: 60000,
  })

  const filteredAlerts = alerts?.filter((alert) =>
    alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    alert.attack_category?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Security Alerts</h1>
        <p className="text-gray-400 mt-1">Monitor and manage security incidents</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="card p-4 text-center">
          <p className="text-2xl font-bold text-white">{stats?.total_alerts || 0}</p>
          <p className="text-sm text-gray-400">Total</p>
        </div>
        <div className="card p-4 text-center border-l-4 border-red-500">
          <p className="text-2xl font-bold text-red-400">{stats?.new_alerts || 0}</p>
          <p className="text-sm text-gray-400">New</p>
        </div>
        <div className="card p-4 text-center border-l-4 border-yellow-500">
          <p className="text-2xl font-bold text-yellow-400">{stats?.investigating_alerts || 0}</p>
          <p className="text-sm text-gray-400">Investigating</p>
        </div>
        <div className="card p-4 text-center border-l-4 border-green-500">
          <p className="text-2xl font-bold text-green-400">{stats?.resolved_alerts || 0}</p>
          <p className="text-sm text-gray-400">Resolved</p>
        </div>
        <div className="card p-4 text-center border-l-4 border-gray-500">
          <p className="text-2xl font-bold text-gray-400">{stats?.false_positives || 0}</p>
          <p className="text-sm text-gray-400">False Positives</p>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-4">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search alerts..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input w-full pl-10"
          />
        </div>

        {/* Severity filter */}
        <div className="relative">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as AlertSeverity | '')}
            className="input appearance-none pr-10 min-w-[150px]"
          >
            <option value="">All Severities</option>
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
          <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400 pointer-events-none" />
        </div>

        {/* Status filter */}
        <div className="relative">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as AlertStatus | '')}
            className="input appearance-none pr-10 min-w-[150px]"
          >
            <option value="">All Statuses</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s.replace('_', ' ').charAt(0).toUpperCase() + s.replace('_', ' ').slice(1)}
              </option>
            ))}
          </select>
          <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400 pointer-events-none" />
        </div>
      </div>

      {/* Alerts Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left text-sm text-gray-400 border-b border-dark-border bg-dark-bg">
                <th className="px-6 py-4">Time</th>
                <th className="px-6 py-4">Severity</th>
                <th className="px-6 py-4">Title</th>
                <th className="px-6 py-4">Source</th>
                <th className="px-6 py-4">Category</th>
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500 mx-auto" />
                  </td>
                </tr>
              ) : filteredAlerts?.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-gray-400">
                    No alerts found
                  </td>
                </tr>
              ) : (
                filteredAlerts?.map((alert) => (
                  <tr
                    key={alert.id}
                    className="border-b border-dark-border hover:bg-dark-border/50 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-4 text-sm text-gray-300">
                      {format(new Date(alert.timestamp), 'MMM d, HH:mm')}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`badge badge-${alert.severity}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-white font-medium max-w-xs truncate">
                      {alert.title}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-300 font-mono">
                      {alert.src_ip || 'N/A'}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-300">
                      {alert.attack_category || 'Unknown'}
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={clsx(
                          'px-2 py-1 rounded text-xs font-medium',
                          alert.status === 'new' && 'bg-blue-500/20 text-blue-400',
                          alert.status === 'investigating' && 'bg-yellow-500/20 text-yellow-400',
                          alert.status === 'resolved' && 'bg-green-500/20 text-green-400',
                          alert.status === 'false_positive' && 'bg-gray-500/20 text-gray-400'
                        )}
                      >
                        {alert.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-300">
                      {alert.confidence ? `${(alert.confidence * 100).toFixed(0)}%` : 'N/A'}
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
