import { useState } from 'react'
import { useAuthStore } from '@/store/authStore'
import { User, Bell, Shield, Database } from 'lucide-react'

/**
 * Settings page with user profile and system configuration
 */
export default function SettingsPage() {
  const { user } = useAuthStore()
  const [activeTab, setActiveTab] = useState('profile')

  const tabs = [
    { id: 'profile', name: 'Profile', icon: User },
    { id: 'notifications', name: 'Notifications', icon: Bell },
    { id: 'security', name: 'Security', icon: Shield },
    { id: 'system', name: 'System', icon: Database },
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-gray-400 mt-1">Manage your account and system preferences</p>
      </div>

      <div className="flex gap-6">
        {/* Sidebar */}
        <div className="w-64 shrink-0">
          <nav className="card p-2 space-y-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'bg-primary-600 text-white'
                    : 'text-gray-400 hover:bg-dark-border hover:text-white'
                }`}
              >
                <tab.icon className="h-5 w-5 mr-3" />
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1 card p-6">
          {activeTab === 'profile' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">Profile Settings</h2>

              <div className="flex items-center space-x-4">
                <div className="w-20 h-20 rounded-full bg-primary-600 flex items-center justify-center text-2xl font-bold text-white">
                  {user?.username?.[0]?.toUpperCase() || 'U'}
                </div>
                <div>
                  <p className="text-lg font-medium text-white">{user?.full_name || user?.username}</p>
                  <p className="text-gray-400">{user?.email}</p>
                  <p className="text-sm text-primary-400 capitalize">{user?.role}</p>
                </div>
              </div>

              <div className="grid gap-4 max-w-md">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Username
                  </label>
                  <input
                    type="text"
                    value={user?.username || ''}
                    disabled
                    className="input w-full opacity-50"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Email
                  </label>
                  <input
                    type="email"
                    value={user?.email || ''}
                    disabled
                    className="input w-full opacity-50"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Full Name
                  </label>
                  <input
                    type="text"
                    defaultValue={user?.full_name || ''}
                    className="input w-full"
                  />
                </div>
                <button className="btn-primary w-fit">Save Changes</button>
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">Notification Settings</h2>

              <div className="space-y-4">
                {[
                  { label: 'Critical alerts', desc: 'Receive notifications for critical severity alerts', default: true },
                  { label: 'High alerts', desc: 'Receive notifications for high severity alerts', default: true },
                  { label: 'Medium alerts', desc: 'Receive notifications for medium severity alerts', default: false },
                  { label: 'Low alerts', desc: 'Receive notifications for low severity alerts', default: false },
                  { label: 'Daily digest', desc: 'Receive a daily summary of all alerts', default: true },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between p-4 bg-dark-bg rounded-lg">
                    <div>
                      <p className="font-medium text-white">{item.label}</p>
                      <p className="text-sm text-gray-400">{item.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" defaultChecked={item.default} className="sr-only peer" />
                      <div className="w-11 h-6 bg-dark-border peer-focus:ring-2 peer-focus:ring-primary-500 rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                    </label>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">Security Settings</h2>

              <div className="space-y-4 max-w-md">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Current Password
                  </label>
                  <input type="password" className="input w-full" placeholder="Enter current password" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    New Password
                  </label>
                  <input type="password" className="input w-full" placeholder="Enter new password" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Confirm New Password
                  </label>
                  <input type="password" className="input w-full" placeholder="Confirm new password" />
                </div>
                <button className="btn-primary">Change Password</button>
              </div>
            </div>
          )}

          {activeTab === 'system' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold text-white">System Information</h2>

              <div className="space-y-4">
                <div className="p-4 bg-dark-bg rounded-lg">
                  <p className="text-sm text-gray-400">Version</p>
                  <p className="font-medium text-white">SentinelFlow v0.1.0</p>
                </div>
                <div className="p-4 bg-dark-bg rounded-lg">
                  <p className="text-sm text-gray-400">Database</p>
                  <p className="font-medium text-white">TimescaleDB (PostgreSQL)</p>
                </div>
                <div className="p-4 bg-dark-bg rounded-lg">
                  <p className="text-sm text-gray-400">ML Engine</p>
                  <p className="font-medium text-white">XGBoost + Isolation Forest</p>
                </div>
                <div className="p-4 bg-dark-bg rounded-lg">
                  <p className="text-sm text-gray-400">GPU</p>
                  <p className="font-medium text-white">NVIDIA RTX 4090 (24GB VRAM)</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
