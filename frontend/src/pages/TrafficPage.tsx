import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, Search, Filter, RefreshCw } from 'lucide-react'
import { format } from 'date-fns'
import { trafficApi } from '@/services/api'
import { useTrafficStream } from '@/services/websocket'
import { clsx } from 'clsx'

/**
 * Network traffic monitoring page
 */
export default function TrafficPage() {
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')

  // Real-time traffic from WebSocket
  const liveTraffic = useTrafficStream()

  // Historical traffic from API
  const { data: traffic, isLoading, refetch } = useQuery({
    queryKey: ['traffic', showAnomaliesOnly],
    queryFn: () =>
      showAnomaliesOnly
        ? trafficApi.getAnomalies(100)
        : trafficApi.list({ limit: 100 }),
    refetchInterval: 10000,
  })

  const { data: stats } = useQuery({
    queryKey: ['traffic-stats'],
    queryFn: () => trafficApi.getStats(),
    refetchInterval: 30000,
  })

  // Combine live and historical, preferring live data
  const allTraffic = [...liveTraffic, ...(traffic || [])].slice(0, 100)

  const filteredTraffic = allTraffic.filter((t) =>
    t.src_ip.includes(searchTerm) ||
    t.dst_ip.includes(searchTerm) ||
    t.protocol?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Network Traffic</h1>
          <p className="text-gray-400 mt-1">Real-time traffic monitoring and analysis</p>
        </div>
        <button
          onClick={() => refetch()}
          className="btn-secondary flex items-center"
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <p className="text-sm text-gray-400">Total Flows</p>
          <p className="text-xl font-bold text-white">
            {stats?.total_flows.toLocaleString() || 0}
          </p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-gray-400">Total Data</p>
          <p className="text-xl font-bold text-white">
            {((stats?.total_bytes || 0) / 1024 / 1024).toFixed(2)} MB
          </p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-gray-400">Anomalies</p>
          <p className="text-xl font-bold text-red-400">
            {stats?.anomaly_count || 0}
          </p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-gray-400">Anomaly Rate</p>
          <p className="text-xl font-bold text-yellow-400">
            {stats?.anomaly_percentage || 0}%
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-4 items-center">
        {/* Live indicator */}
        <div className="flex items-center text-sm">
          <span className="w-2 h-2 rounded-full bg-green-500 live-pulse mr-2" />
          <span className="text-green-400">Live</span>
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search by IP or protocol..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input w-full pl-10"
          />
        </div>

        {/* Anomalies filter */}
        <label className="flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={showAnomaliesOnly}
            onChange={(e) => setShowAnomaliesOnly(e.target.checked)}
            className="sr-only"
          />
          <div
            className={clsx(
              'w-10 h-6 rounded-full transition-colors',
              showAnomaliesOnly ? 'bg-primary-600' : 'bg-dark-border'
            )}
          >
            <div
              className={clsx(
                'w-4 h-4 rounded-full bg-white mt-1 transition-transform',
                showAnomaliesOnly ? 'translate-x-5' : 'translate-x-1'
              )}
            />
          </div>
          <span className="ml-2 text-sm text-gray-400">Anomalies only</span>
        </label>
      </div>

      {/* Traffic Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left text-sm text-gray-400 border-b border-dark-border bg-dark-bg">
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Destination</th>
                <th className="px-4 py-3">Protocol</th>
                <th className="px-4 py-3">Bytes</th>
                <th className="px-4 py-3">Packets</th>
                <th className="px-4 py-3">Anomaly</th>
                <th className="px-4 py-3">Category</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && liveTraffic.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500 mx-auto" />
                  </td>
                </tr>
              ) : filteredTraffic.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-400">
                    No traffic data
                  </td>
                </tr>
              ) : (
                filteredTraffic.map((t, idx) => (
                  <tr
                    key={`${t.id}-${idx}`}
                    className={clsx(
                      'border-b border-dark-border transition-colors',
                      t.is_anomaly
                        ? 'bg-red-500/5 hover:bg-red-500/10'
                        : 'hover:bg-dark-border/50'
                    )}
                  >
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {format(new Date(t.timestamp), 'HH:mm:ss')}
                    </td>
                    <td className="px-4 py-3 text-sm font-mono text-white">
                      {t.src_ip}
                      {t.src_port && <span className="text-gray-500">:{t.src_port}</span>}
                    </td>
                    <td className="px-4 py-3 text-sm font-mono text-white">
                      {t.dst_ip}
                      {t.dst_port && <span className="text-gray-500">:{t.dst_port}</span>}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {t.protocol || 'Unknown'}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {(t.bytes_sent + t.bytes_received).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {t.packets_sent + t.packets_received}
                    </td>
                    <td className="px-4 py-3">
                      {t.is_anomaly ? (
                        <span className="badge badge-high">
                          {(t.anomaly_score! * 100).toFixed(0)}%
                        </span>
                      ) : (
                        <span className="text-gray-500 text-sm">Normal</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-300">
                      {t.attack_category || '-'}
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
