import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play,
  Square,
  Wifi,
  Clock,
  AlertTriangle,
  Target,
  Loader2,
  CheckCircle,
  XCircle,
} from 'lucide-react'
import { clsx } from 'clsx'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

interface NetworkInterface {
  name: string
  ip: string
  description: string
}

interface MonitoringStatus {
  is_capturing: boolean
  interface: string
  target_ip: string
  duration: number
  elapsed: number
  remaining: number
  packets_captured: number
  flows_detected: number
  total_alerts: number
  attacks_detected: number
}

/**
 * Real-Time Network Monitoring Panel
 *
 * Allows users to:
 * - Select network interface to monitor
 * - Set target IP/subnet (optional filter)
 * - Set monitoring duration
 * - Start/stop packet capture
 * - View real-time statistics
 */
export default function MonitoringPanel() {
  const queryClient = useQueryClient()

  // Form state
  const [selectedInterface, setSelectedInterface] = useState('')
  const [targetIp, setTargetIp] = useState('')
  const [duration, setDuration] = useState(60)
  const [customDuration, setCustomDuration] = useState('')
  const [showCustomInput, setShowCustomInput] = useState(false)

  // Error state
  const [error, setError] = useState<string | null>(null)

  // WebSocket connection state
  const [wsConnected, setWsConnected] = useState(false)
  const [liveStats, setLiveStats] = useState<Partial<MonitoringStatus>>({})

  // Fetch available interfaces
  const { data: interfacesData, isLoading: loadingInterfaces } = useQuery({
    queryKey: ['monitor-interfaces'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/monitor/interfaces`)
      return res.json()
    },
  })

  // Fetch current monitoring status
  const { data: status, refetch: refetchStatus } = useQuery({
    queryKey: ['monitor-status'],
    queryFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/monitor/status`)
      return res.json() as Promise<MonitoringStatus>
    },
    refetchInterval: 2000, // Poll every 2 seconds when monitoring
  })

  // Start monitoring mutation
  const startMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/monitor/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: selectedInterface,
          duration: duration,
          target_ip: targetIp || null,
        }),
      })

      // Check response status
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ message: 'Failed to start monitoring' }))
        throw new Error(errorData.message || errorData.detail || 'Failed to start monitoring')
      }

      return res.json()
    },
    onSuccess: (data) => {
      if (data.status === 'error') {
        setError(data.message || 'Failed to start monitoring')
        return
      }
      setError(null)
      refetchStatus()
      queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] })
    },
    onError: (err: Error) => {
      setError(err.message || 'Failed to start monitoring')
    },
  })

  // Stop monitoring mutation
  const stopMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch(`${API_URL}/api/v1/monitor/stop`, {
        method: 'POST',
      })
      return res.json()
    },
    onSuccess: () => {
      refetchStatus()
      queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] })
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  // WebSocket connection for real-time updates
  useEffect(() => {
    const wsUrl = `${API_URL.replace('http', 'ws')}/api/v1/ws/monitor`
    let ws: WebSocket | null = null
    let reconnectTimeout: NodeJS.Timeout

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl)

        ws.onopen = () => {
          setWsConnected(true)
          console.log('WebSocket connected for monitoring')
        }

        ws.onmessage = (event) => {
          const data = JSON.parse(event.data)

          if (data.type === 'status') {
            setLiveStats(data.data)
          } else if (data.type === 'alert') {
            // Refresh alerts when new one arrives
            queryClient.invalidateQueries({ queryKey: ['alerts'] })
            queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] })
          } else if (data.type === 'flow') {
            // Update traffic data
            queryClient.invalidateQueries({ queryKey: ['traffic'] })
          }
        }

        ws.onclose = () => {
          setWsConnected(false)
          // Reconnect after 3 seconds
          reconnectTimeout = setTimeout(connect, 3000)
        }

        ws.onerror = () => {
          setWsConnected(false)
        }
      } catch (error) {
        console.error('WebSocket connection error:', error)
      }
    }

    connect()

    return () => {
      if (ws) ws.close()
      if (reconnectTimeout) clearTimeout(reconnectTimeout)
    }
  }, [queryClient])

  const interfaces: NetworkInterface[] = interfacesData?.interfaces || []
  const isMonitoring = status?.is_capturing || false
  const currentStats = isMonitoring ? { ...status, ...liveStats } : status

  // Calculate progress percentage
  const progress = currentStats?.duration
    ? Math.min(100, ((currentStats.elapsed || 0) / currentStats.duration) * 100)
    : 0

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className={clsx(
            'p-2 rounded-lg',
            isMonitoring ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
          )}>
            <Wifi className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-white">Network Monitoring</h2>
            <p className="text-sm text-gray-400">
              {isMonitoring ? 'Capturing real network traffic...' : 'Configure and start monitoring'}
            </p>
          </div>
        </div>

        {/* WebSocket Status */}
        <div className={clsx(
          'flex items-center text-xs px-2 py-1 rounded',
          wsConnected ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
        )}>
          {wsConnected ? (
            <>
              <CheckCircle className="h-3 w-3 mr-1" />
              Live
            </>
          ) : (
            <>
              <XCircle className="h-3 w-3 mr-1" />
              Offline
            </>
          )}
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-500/20 border border-red-500 rounded-lg p-3 mb-4 text-red-400 text-sm flex items-center">
          <AlertTriangle className="h-4 w-4 mr-2 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Configuration Form */}
      {!isMonitoring && (
        <div className="space-y-4 mb-6">
          {/* Interface Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Network Interface
            </label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              className="w-full bg-dark-card border border-dark-border rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
              disabled={loadingInterfaces}
            >
              <option value="">Select interface...</option>
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.description}
                </option>
              ))}
            </select>
          </div>

          {/* Target IP (Optional) */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              <Target className="h-4 w-4 inline mr-1" />
              Target IP/Subnet (Optional)
            </label>
            <input
              type="text"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              placeholder="e.g., 192.168.1.100 or 192.168.1.0/24"
              className="w-full bg-dark-card border border-dark-border rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
            <p className="text-xs text-gray-500 mt-1">
              Leave empty to capture all traffic on the interface
            </p>
          </div>

          {/* Duration Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              <Clock className="h-4 w-4 inline mr-1" />
              Monitoring Duration
            </label>
            <div className="grid grid-cols-5 gap-2">
              {[30, 60, 300, 600].map((sec) => (
                <button
                  key={sec}
                  onClick={() => {
                    setDuration(sec)
                    setShowCustomInput(false)
                    setCustomDuration('')
                  }}
                  className={clsx(
                    'px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                    duration === sec && !showCustomInput
                      ? 'bg-primary-500 text-white'
                      : 'bg-dark-card border border-dark-border text-gray-300 hover:bg-dark-border'
                  )}
                >
                  {sec < 60 ? `${sec}s` : `${sec / 60}m`}
                </button>
              ))}
              <button
                onClick={() => setShowCustomInput(!showCustomInput)}
                className={clsx(
                  'px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                  showCustomInput
                    ? 'bg-primary-500 text-white'
                    : 'bg-dark-card border border-dark-border text-gray-300 hover:bg-dark-border'
                )}
              >
                Custom
              </button>
            </div>
            {showCustomInput && (
              <div className="mt-3">
                <input
                  type="number"
                  value={customDuration}
                  onChange={(e) => {
                    setCustomDuration(e.target.value)
                    const val = parseInt(e.target.value)
                    if (val > 0 && val <= 3600) {
                      setDuration(val)
                    }
                  }}
                  placeholder="Enter seconds (10-3600)"
                  min="10"
                  max="3600"
                  className="w-full bg-dark-card border border-dark-border rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Current: {duration}s ({Math.floor(duration / 60)}m {duration % 60}s)
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Monitoring Status */}
      {isMonitoring && currentStats && (
        <div className="space-y-4 mb-6">
          {/* Progress Bar */}
          <div>
            <div className="flex justify-between text-sm text-gray-400 mb-2">
              <span>Progress</span>
              <span>{Math.round(currentStats.remaining || 0)}s remaining</span>
            </div>
            <div className="h-2 bg-dark-border rounded-full overflow-hidden">
              <div
                className="h-full bg-primary-500 transition-all duration-1000"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>

          {/* Live Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-dark-card/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-white">
                {currentStats.packets_captured?.toLocaleString() || 0}
              </p>
              <p className="text-xs text-gray-400">Packets</p>
            </div>
            <div className="bg-dark-card/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-white">
                {currentStats.flows_detected?.toLocaleString() || 0}
              </p>
              <p className="text-xs text-gray-400">Flows</p>
            </div>
            <div className="bg-dark-card/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-yellow-400">
                {currentStats.attacks_detected || 0}
              </p>
              <p className="text-xs text-gray-400">Attacks</p>
            </div>
            <div className="bg-dark-card/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-red-400">
                {currentStats.total_alerts || 0}
              </p>
              <p className="text-xs text-gray-400">Alerts</p>
            </div>
          </div>

          {/* Monitoring Info */}
          <div className="bg-dark-card/30 rounded-lg p-3 text-sm">
            <p className="text-gray-400">
              <span className="text-gray-300">Interface:</span> {currentStats.interface}
            </p>
            {currentStats.target_ip && (
              <p className="text-gray-400">
                <span className="text-gray-300">Target:</span> {currentStats.target_ip}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex space-x-3">
        {!isMonitoring ? (
          <button
            onClick={() => {
              setError(null)
              startMutation.mutate()
            }}
            disabled={!selectedInterface || startMutation.isPending}
            className={clsx(
              'flex-1 flex items-center justify-center px-4 py-3 rounded-lg font-medium transition-colors',
              selectedInterface
                ? 'bg-green-500 hover:bg-green-600 text-white'
                : 'bg-gray-600 text-gray-400 cursor-not-allowed'
            )}
          >
            {startMutation.isPending ? (
              <Loader2 className="h-5 w-5 mr-2 animate-spin" />
            ) : (
              <Play className="h-5 w-5 mr-2" />
            )}
            Start Monitoring
          </button>
        ) : (
          <button
            onClick={() => stopMutation.mutate()}
            disabled={stopMutation.isPending}
            className="flex-1 flex items-center justify-center px-4 py-3 rounded-lg font-medium bg-red-500 hover:bg-red-600 text-white transition-colors"
          >
            {stopMutation.isPending ? (
              <Loader2 className="h-5 w-5 mr-2 animate-spin" />
            ) : (
              <Square className="h-5 w-5 mr-2" />
            )}
            Stop Monitoring
          </button>
        )}
      </div>

      {/* Help Text */}
      <p className="text-xs text-gray-500 mt-4 text-center">
        {isMonitoring
          ? 'ML models are analyzing traffic in real-time. Alerts will appear automatically.'
          : 'Note: Packet capture requires the backend to run with sudo/root privileges.'}
      </p>
    </div>
  )
}
