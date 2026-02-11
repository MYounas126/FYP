import { useEffect, useRef, useCallback, useState } from 'react'
import type { WSMessage, WSTrafficMessage, WSAlertMessage } from '@/types'

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000'

type MessageHandler = (message: WSMessage) => void

/**
 * WebSocket connection manager
 */
class WebSocketManager {
  private ws: WebSocket | null = null
  private handlers: Set<MessageHandler> = new Set()
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectDelay = 1000

  connect(endpoint: string = '/api/v1/ws/live'): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return
    }

    try {
      this.ws = new WebSocket(`${WS_URL}${endpoint}`)

      this.ws.onopen = () => {
        console.log('WebSocket connected')
        this.reconnectAttempts = 0
      }

      this.ws.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data)
          this.handlers.forEach((handler) => handler(message))
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e)
        }
      }

      this.ws.onclose = () => {
        console.log('WebSocket disconnected')
        this.attemptReconnect(endpoint)
      }

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }
    } catch (error) {
      console.error('Failed to create WebSocket:', error)
    }
  }

  private attemptReconnect(endpoint: string): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('Max reconnection attempts reached')
      return
    }

    this.reconnectAttempts++
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1)

    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`)

    setTimeout(() => {
      this.connect(endpoint)
    }, delay)
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }

  subscribe(handler: MessageHandler): () => void {
    this.handlers.add(handler)
    return () => this.handlers.delete(handler)
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }
}

// Singleton instance
export const wsManager = new WebSocketManager()

/**
 * React hook for WebSocket connection
 */
export function useWebSocket(endpoint: string = '/api/v1/ws/live') {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null)

  useEffect(() => {
    // Only connect in production or when WebSocket is available
    try {
      wsManager.connect(endpoint)
    } catch (e) {
      console.warn('WebSocket connection failed, running in offline mode')
    }

    const unsubscribe = wsManager.subscribe((message) => {
      setLastMessage(message)
      if (message.type === 'connection') {
        setIsConnected(true)
      }
    })

    // Check connection status periodically
    const interval = setInterval(() => {
      setIsConnected(wsManager.isConnected())
    }, 1000)

    return () => {
      unsubscribe()
      clearInterval(interval)
    }
  }, [endpoint])

  return { isConnected, lastMessage }
}

/**
 * React hook for real-time traffic updates
 */
export function useTrafficStream() {
  const [traffic, setTraffic] = useState<WSTrafficMessage['data'][]>([])
  const maxItems = 100

  useEffect(() => {
    const unsubscribe = wsManager.subscribe((message) => {
      if (message.type === 'traffic') {
        const trafficMsg = message as WSTrafficMessage
        setTraffic((prev) => {
          const updated = [trafficMsg.data, ...prev]
          return updated.slice(0, maxItems)
        })
      }
    })

    return unsubscribe
  }, [])

  return traffic
}

/**
 * React hook for real-time alert updates
 */
export function useAlertStream() {
  const [alerts, setAlerts] = useState<WSAlertMessage['data'][]>([])
  const [newAlertCount, setNewAlertCount] = useState(0)

  useEffect(() => {
    const unsubscribe = wsManager.subscribe((message) => {
      if (message.type === 'alert') {
        const alertMsg = message as WSAlertMessage
        setAlerts((prev) => [alertMsg.data, ...prev])
        setNewAlertCount((count) => count + 1)
      }
    })

    return unsubscribe
  }, [])

  const clearNewAlerts = useCallback(() => {
    setNewAlertCount(0)
  }, [])

  return { alerts, newAlertCount, clearNewAlerts }
}
