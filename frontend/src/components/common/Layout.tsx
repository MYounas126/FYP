import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard,
  AlertTriangle,
  Activity,
  Settings,
  LogOut,
  Shield,
  Bell,
} from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { useWebSocket, useAlertStream } from '@/services/websocket'
import { clsx } from 'clsx'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
  { name: 'Traffic', href: '/traffic', icon: Activity },
  { name: 'Settings', href: '/settings', icon: Settings },
]

/**
 * Main application layout with sidebar navigation
 */
export default function Layout() {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const { isConnected } = useWebSocket()
  const { newAlertCount } = useAlertStream()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen bg-dark-bg">
      {/* Sidebar */}
      <aside className="w-64 bg-dark-card border-r border-dark-border flex flex-col">
        {/* Logo */}
        <div className="h-16 flex items-center px-6 border-b border-dark-border">
          <Shield className="h-8 w-8 text-primary-500" />
          <span className="ml-3 text-xl font-bold text-white">SentinelFlow</span>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-6 space-y-2">
          {navigation.map((item) => (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive }) =>
                clsx(
                  'flex items-center px-4 py-3 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-primary-600 text-white'
                    : 'text-gray-400 hover:bg-dark-border hover:text-white'
                )
              }
            >
              <item.icon className="h-5 w-5 mr-3" />
              {item.name}
              {item.name === 'Alerts' && newAlertCount > 0 && (
                <span className="ml-auto bg-red-500 text-white text-xs px-2 py-0.5 rounded-full">
                  {newAlertCount}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Connection Status */}
        <div className="px-6 py-4 border-t border-dark-border">
          <div className="flex items-center text-sm">
            <span
              className={clsx(
                'w-2 h-2 rounded-full mr-2',
                isConnected ? 'bg-green-500 live-pulse' : 'bg-red-500'
              )}
            />
            <span className="text-gray-400">
              {isConnected ? 'Live' : 'Disconnected'}
            </span>
          </div>
        </div>

        {/* User section */}
        <div className="px-4 py-4 border-t border-dark-border">
          <div className="flex items-center">
            <div className="w-10 h-10 rounded-full bg-primary-600 flex items-center justify-center">
              <span className="text-white font-medium">
                {user?.username?.[0]?.toUpperCase() || 'U'}
              </span>
            </div>
            <div className="ml-3 flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">
                {user?.username || 'User'}
              </p>
              <p className="text-xs text-gray-400 capitalize">
                {user?.role || 'observer'}
              </p>
            </div>
            <button
              onClick={handleLogout}
              className="p-2 text-gray-400 hover:text-white transition-colors"
              title="Logout"
            >
              <LogOut className="h-5 w-5" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        {/* Header */}
        <header className="h-16 bg-dark-card border-b border-dark-border flex items-center justify-between px-6">
          <h1 className="text-lg font-semibold text-white">
            Network Intrusion Detection System
          </h1>
          <div className="flex items-center space-x-4">
            <button className="relative p-2 text-gray-400 hover:text-white transition-colors">
              <Bell className="h-5 w-5" />
              {newAlertCount > 0 && (
                <span className="absolute top-0 right-0 w-4 h-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                  {newAlertCount > 9 ? '9+' : newAlertCount}
                </span>
              )}
            </button>
          </div>
        </header>

        {/* Page content */}
        <div className="p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
