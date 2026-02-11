import axios, { AxiosError, AxiosInstance } from 'axios'
import { useAuthStore } from '@/store/authStore'
import type {
  User,
  AuthTokens,
  LoginCredentials,
  Alert,
  AlertStats,
  AlertQueryParams,
  NetworkTraffic,
  TrafficStats,
  TrafficQueryParams,
  DashboardOverview,
  TimelineData,
} from '@/types'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

/**
 * Create axios instance with interceptors
 */
const createApiClient = (): AxiosInstance => {
  const client = axios.create({
    baseURL: `${API_URL}/api/v1`,
    headers: {
      'Content-Type': 'application/json',
    },
  })

  // Request interceptor - add auth token
  client.interceptors.request.use((config) => {
    const { tokens } = useAuthStore.getState()
    if (tokens?.access_token) {
      config.headers.Authorization = `Bearer ${tokens.access_token}`
    }
    return config
  })

  // Response interceptor - handle errors
  client.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      if (error.response?.status === 401) {
        // Token expired, logout
        useAuthStore.getState().logout()
      }
      return Promise.reject(error)
    }
  )

  return client
}

const api = createApiClient()

// =============================================================================
// Auth API
// =============================================================================

export const authApi = {
  login: async (credentials: LoginCredentials): Promise<AuthTokens> => {
    const response = await api.post<AuthTokens>('/auth/login', credentials)
    return response.data
  },

  getMe: async (): Promise<User> => {
    const response = await api.get<User>('/auth/me')
    return response.data
  },

  refresh: async (refreshToken: string): Promise<AuthTokens> => {
    const response = await api.post<AuthTokens>('/auth/refresh', null, {
      params: { refresh_token: refreshToken },
    })
    return response.data
  },
}

// =============================================================================
// Dashboard API
// =============================================================================

export const dashboardApi = {
  getOverview: async (): Promise<DashboardOverview> => {
    const response = await api.get<DashboardOverview>('/dashboard/overview')
    return response.data
  },

  getTimeline: async (hours: number = 24): Promise<TimelineData> => {
    const response = await api.get<TimelineData>('/dashboard/timeline', {
      params: { hours },
    })
    return response.data
  },

  getAttackDistribution: async (): Promise<Array<{ category: string; count: number }>> => {
    const response = await api.get('/dashboard/attack-distribution')
    return response.data
  },
}

// =============================================================================
// Traffic API
// =============================================================================

export const trafficApi = {
  list: async (params?: TrafficQueryParams): Promise<NetworkTraffic[]> => {
    const response = await api.get<NetworkTraffic[]>('/traffic', { params })
    return response.data
  },

  getStats: async (startTime?: string, endTime?: string): Promise<TrafficStats> => {
    const response = await api.get<TrafficStats>('/traffic/stats', {
      params: { start_time: startTime, end_time: endTime },
    })
    return response.data
  },

  getAnomalies: async (limit: number = 100): Promise<NetworkTraffic[]> => {
    const response = await api.get<NetworkTraffic[]>('/traffic/anomalies', {
      params: { limit },
    })
    return response.data
  },
}

// =============================================================================
// Alerts API
// =============================================================================

export const alertsApi = {
  list: async (params?: AlertQueryParams): Promise<Alert[]> => {
    const response = await api.get<Alert[]>('/alerts', { params })
    return response.data
  },

  get: async (id: string): Promise<Alert> => {
    const response = await api.get<Alert>(`/alerts/${id}`)
    return response.data
  },

  update: async (id: string, data: Partial<Alert>): Promise<Alert> => {
    const response = await api.patch<Alert>(`/alerts/${id}`, data)
    return response.data
  },

  getStats: async (startTime?: string, endTime?: string): Promise<AlertStats> => {
    const response = await api.get<AlertStats>('/alerts/stats', {
      params: { start_time: startTime, end_time: endTime },
    })
    return response.data
  },
}

// =============================================================================
// Users API
// =============================================================================

export const usersApi = {
  list: async (): Promise<User[]> => {
    const response = await api.get<User[]>('/users')
    return response.data
  },

  get: async (id: string): Promise<User> => {
    const response = await api.get<User>(`/users/${id}`)
    return response.data
  },

  create: async (data: Partial<User> & { password: string }): Promise<User> => {
    const response = await api.post<User>('/users', data)
    return response.data
  },

  update: async (id: string, data: Partial<User>): Promise<User> => {
    const response = await api.patch<User>(`/users/${id}`, data)
    return response.data
  },

  delete: async (id: string): Promise<void> => {
    await api.delete(`/users/${id}`)
  },
}

export default api
