import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, Loader2, UserPlus, ArrowLeft } from 'lucide-react'
import { authApi } from '@/services/api'

/**
 * Register page component
 */
export default function RegisterPage() {
    const navigate = useNavigate()

    const [formData, setFormData] = useState({
        username: '',
        email: '',
        fullName: '',
        password: '',
        confirmPassword: '',
    })

    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState('')
    const [success, setSuccess] = useState('')

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target
        setFormData(prev => ({ ...prev, [name]: value }))
    }

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError('')
        setSuccess('')

        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match')
            return
        }

        setIsLoading(true)

        try {
            await authApi.register({
                username: formData.username,
                email: formData.email,
                password: formData.password,
                full_name: formData.fullName || undefined,
            })

            setSuccess('Registration successful! Redirecting to login...')

            // Redirect to login after a short delay
            setTimeout(() => {
                navigate('/login')
            }, 2000)
        } catch (err: any) {
            if (err.response?.data?.detail) {
                setError(err.response.data.detail)
            } else {
                setError('Registration failed. Please try again.')
            }
        } finally {
            setIsLoading(false)
        }
    }

    return (
        <div className="min-h-screen bg-dark-bg flex items-center justify-center p-4">
            <div className="w-full max-w-md">
                {/* Logo */}
                <div className="text-center mb-8">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-primary-600 mb-4">
                        <Shield className="h-8 w-8 text-white" />
                    </div>
                    <h1 className="text-2xl font-bold text-white">SentinelFlow</h1>
                    <p className="text-gray-400 mt-2">Create your account</p>
                </div>

                {/* Register form */}
                <div className="card p-8">
                    <h2 className="text-xl font-semibold text-white mb-6 flex items-center">
                        <UserPlus className="h-5 w-5 mr-2 text-primary-500" />
                        Sign Up
                    </h2>

                    <form onSubmit={handleSubmit} className="space-y-4">
                        {/* Error message */}
                        {error && (
                            <div className="bg-red-500/10 border border-red-500/50 text-red-400 px-4 py-3 rounded-lg text-sm">
                                {error}
                            </div>
                        )}

                        {/* Success message */}
                        {success && (
                            <div className="bg-green-500/10 border border-green-500/50 text-green-400 px-4 py-3 rounded-lg text-sm">
                                {success}
                            </div>
                        )}

                        {/* Username */}
                        <div>
                            <label htmlFor="username" className="block text-sm font-medium text-gray-300 mb-1">
                                Username
                            </label>
                            <input
                                id="username"
                                name="username"
                                type="text"
                                value={formData.username}
                                onChange={handleChange}
                                className="input w-full"
                                placeholder="Choose a username"
                                required
                                minLength={3}
                            />
                        </div>

                        {/* Email */}
                        <div>
                            <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-1">
                                Email
                            </label>
                            <input
                                id="email"
                                name="email"
                                type="email"
                                value={formData.email}
                                onChange={handleChange}
                                className="input w-full"
                                placeholder="Enter your email"
                                required
                            />
                        </div>

                        {/* Full Name */}
                        <div>
                            <label htmlFor="fullName" className="block text-sm font-medium text-gray-300 mb-1">
                                Full Name (Optional)
                            </label>
                            <input
                                id="fullName"
                                name="fullName"
                                type="text"
                                value={formData.fullName}
                                onChange={handleChange}
                                className="input w-full"
                                placeholder="Enter your full name"
                            />
                        </div>

                        {/* Password */}
                        <div>
                            <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-1">
                                Password
                            </label>
                            <input
                                id="password"
                                name="password"
                                type="password"
                                value={formData.password}
                                onChange={handleChange}
                                className="input w-full"
                                placeholder="Create a password"
                                required
                                minLength={6}
                            />
                        </div>

                        {/* Confirm Password */}
                        <div>
                            <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-300 mb-1">
                                Confirm Password
                            </label>
                            <input
                                id="confirmPassword"
                                name="confirmPassword"
                                type="password"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                className="input w-full"
                                placeholder="Confirm your password"
                                required
                            />
                        </div>

                        {/* Submit button */}
                        <button
                            type="submit"
                            disabled={isLoading || !!success}
                            className="btn-primary w-full flex items-center justify-center mt-6"
                        >
                            {isLoading ? (
                                <>
                                    <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                                    Creating account...
                                </>
                            ) : (
                                'Create Account'
                            )}
                        </button>
                    </form>

                    <div className="mt-6 text-center">
                        <Link to="/login" className="text-primary-400 hover:text-primary-300 text-sm flex items-center justify-center">
                            <ArrowLeft className="h-4 w-4 mr-1" />
                            Back to Sign In
                        </Link>
                    </div>
                </div>

                {/* Footer */}
                <p className="text-center text-gray-500 text-sm mt-6">
                    SentinelFlow v0.1.0 - GIKI FYP 2026
                </p>
            </div>
        </div>
    )
}
