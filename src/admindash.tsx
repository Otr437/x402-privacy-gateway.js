import React, { useState, useEffect } from 'react';
import { Activity, DollarSign, TrendingUp, Shield, Users, Clock, ExternalLink, RefreshCw, Loader2, Eye, Search, Filter } from 'lucide-react';

const API_BASE = 'http://localhost:3402/api/v1';

export default function AdminDashboard() {
  const [view, setView] = useState('login');
  const [token, setToken] = useState(localStorage.getItem('x402_admin_token'));
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (token) {
      setView('dashboard');
    }
  }, [token]);

  const handleLogin = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE}/admin/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      localStorage.setItem('x402_admin_token', data.token);
      localStorage.setItem('x402_admin_user', JSON.stringify(data.user));
      setToken(data.token);
      setView('dashboard');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSetup = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE}/admin/auth/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      localStorage.setItem('x402_admin_token', data.token);
      localStorage.setItem('x402_admin_user', JSON.stringify(data.user));
      setToken(data.token);
      setView('dashboard');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (!token || view === 'login') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center p-4">
        <div className="w-full max-w-md bg-slate-800/50 backdrop-blur-sm rounded-2xl p-8 border border-white/10 shadow-2xl">
          <div className="text-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-pink-500 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <Shield className="w-10 h-10 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">Admin Portal</h1>
            <p className="text-gray-400">X402 Payment System</p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
                placeholder="Enter username"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
                placeholder="Enter password (min 8 chars)"
              />
            </div>

            {error && (
              <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-3 text-red-300 text-sm">
                {error}
              </div>
            )}

            <button
              onClick={view === 'setup' ? handleSetup : handleLogin}
              disabled={loading || !username || password.length < 8}
              className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-slate-600 disabled:to-slate-600 text-white font-semibold rounded-lg transition-all shadow-lg disabled:cursor-not-allowed flex items-center justify-center space-x-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>Processing...</span>
                </>
              ) : (
                <span>{view === 'setup' ? 'Create Admin Account' : 'Login'}</span>
              )}
            </button>
          </div>

          <div className="mt-4 text-center">
            <button
              onClick={() => setView(view === 'setup' ? 'login' : 'setup')}
              className="text-purple-400 hover:text-purple-300 text-sm font-medium"
            >
              {view === 'setup' ? 'Already have an account? Login' : 'First time? Setup Account'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <DashboardContent token={token} />
    </div>
  );
}

function DashboardContent({ token }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [dashboard, setDashboard] = useState(null);
  const [payments, setPayments] = useState(null);
  const [privacyRoutes, setPrivacyRoutes] = useState(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    fetchDashboard();
  }, []);

  useEffect(() => {
    if (activeTab === 'payments') fetchPayments();
    if (activeTab === 'privacy') fetchPrivacyRoutes();
  }, [activeTab]);

  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/admin/dashboard`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      setDashboard(data);
    } catch (err) {
      console.error('Failed to fetch dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchPayments = async () => {
    setRefreshing(true);
    try {
      const response = await fetch(`${API_BASE}/admin/payments?limit=100`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      setPayments(data);
    } catch (err) {
      console.error('Failed to fetch payments:', err);
    } finally {
      setRefreshing(false);
    }
  };

  const fetchPrivacyRoutes = async () => {
    setRefreshing(true);
    try {
      const response = await fetch(`${API_BASE}/admin/privacy-routes?limit=100`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error);
      setPrivacyRoutes(data);
    } catch (err) {
      console.error('Failed to fetch privacy routes:', err);
    } finally {
      setRefreshing(false);
    }
  };

  const refresh = () => {
    if (activeTab === 'overview') fetchDashboard();
    if (activeTab === 'payments') fetchPayments();
    if (activeTab === 'privacy') fetchPrivacyRoutes();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="w-12 h-12 text-purple-500 animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-4 lg:p-8">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 to-pink-600 rounded-2xl p-6 text-white mb-6 shadow-2xl">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2">Admin Dashboard</h1>
            <p className="text-purple-100">Monitor and manage X402 payment system</p>
          </div>
          <button
            onClick={refresh}
            disabled={refreshing}
            className="p-3 bg-white/20 hover:bg-white/30 rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-6 h-6 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-2 mb-6 overflow-x-auto">
        <TabButton label="Overview" active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} />
        <TabButton label="Payments" active={activeTab === 'payments'} onClick={() => setActiveTab('payments')} />
        <TabButton label="Privacy Routes" active={activeTab === 'privacy'} onClick={() => setActiveTab('privacy')} />
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && dashboard && (
        <div className="space-y-6">
          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              label="Total Payments"
              value={dashboard.overview.totalPayments}
              icon={<DollarSign className="w-6 h-6 text-blue-400" />}
              color="blue"
            />
            <StatCard
              label="Confirmed"
              value={dashboard.overview.confirmedPayments}
              icon={<Activity className="w-6 h-6 text-green-400" />}
              color="green"
            />
            <StatCard
              label="Privacy Routed"
              value={dashboard.overview.privacyRoutedPayments}
              icon={<Shield className="w-6 h-6 text-purple-400" />}
              color="purple"
            />
            <StatCard
              label="Total Revenue"
              value={`$${parseFloat(dashboard.overview.totalRevenue).toFixed(2)}`}
              icon={<TrendingUp className="w-6 h-6 text-pink-400" />}
              color="pink"
            />
          </div>

          {/* Deposit Wallets */}
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
            <h3 className="text-xl font-bold text-white mb-4">Deposit Wallet Balances</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {dashboard.depositWallets.usdc_base && (
                <WalletCard
                  label="USDC (Base)"
                  balance={dashboard.depositWallets.usdc_base.balance}
                  address={dashboard.depositWallets.usdc_base.address}
                />
              )}
              {dashboard.depositWallets.usdc_polygon && (
                <WalletCard
                  label="USDC (Polygon)"
                  balance={dashboard.depositWallets.usdc_polygon.balance}
                  address={dashboard.depositWallets.usdc_polygon.address}
                />
              )}
              {dashboard.depositWallets.usdc_starknet && (
                <WalletCard
                  label="USDC (StarkNet)"
                  balance={dashboard.depositWallets.usdc_starknet.balance}
                  address={dashboard.depositWallets.usdc_starknet.address}
                />
              )}
              {dashboard.depositWallets.zec_shielded && (
                <WalletCard
                  label="ZEC (Shielded)"
                  balance={`${dashboard.depositWallets.zec_shielded.balance} ZEC`}
                  address={dashboard.depositWallets.zec_shielded.address}
                />
              )}
              {dashboard.depositWallets.zec_transparent && (
                <WalletCard
                  label="ZEC (Transparent)"
                  balance={`${dashboard.depositWallets.zec_transparent.balance} ZEC`}
                  address={dashboard.depositWallets.zec_transparent.address}
                />
              )}
              {dashboard.depositWallets.xmr && (
                <WalletCard
                  label="Monero"
                  balance={`${dashboard.depositWallets.xmr.balance.toFixed(12)} XMR`}
                  address={dashboard.depositWallets.xmr.address}
                />
              )}
            </div>
          </div>

          {/* Privacy Router Status */}
          {dashboard.privacyRouter && (
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
              <h3 className="text-xl font-bold text-white mb-4">Privacy Router Status</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm text-gray-400 mb-1">Status</p>
                  <p className="text-lg font-bold text-white">
                    {dashboard.privacyRouter.enabled ? 'Enabled' : 'Disabled'}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400 mb-1">Multi-Hop</p>
                  <p className="text-lg font-bold text-white">
                    {dashboard.privacyRouter.multiHop ? 'Yes' : 'No'}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-400 mb-1">Queue Size</p>
                  <p className="text-lg font-bold text-white">{dashboard.privacyRouter.queueSize}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400 mb-1">Processing</p>
                  <p className="text-lg font-bold text-white">
                    {dashboard.privacyRouter.processing ? 'Active' : 'Idle'}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Recent Payments */}
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
            <h3 className="text-xl font-bold text-white mb-4">Recent Payments</h3>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-gray-400 text-sm border-b border-white/10">
                    <th className="pb-3">Client</th>
                    <th className="pb-3">Amount</th>
                    <th className="pb-3">Currency</th>
                    <th className="pb-3">Status</th>
                    <th className="pb-3">Type</th>
                    <th className="pb-3">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {dashboard.recentPayments.slice(0, 10).map((payment) => (
                    <tr key={payment.id} className="border-b border-white/5 hover:bg-white/5">
                      <td className="py-3 text-white font-mono text-sm">
                        {payment.clientId.slice(0, 12)}...
                      </td>
                      <td className="py-3 text-white font-semibold">
                        ${payment.usdAmount.toFixed(2)}
                      </td>
                      <td className="py-3">
                        <span className="px-2 py-1 bg-blue-500/20 text-blue-300 rounded text-xs font-medium">
                          {payment.currency}
                        </span>
                      </td>
                      <td className="py-3">
                        <StatusBadge status={payment.status} />
                      </td>
                      <td className="py-3">
                        <span className="text-gray-300 text-sm">{payment.paymentType}</span>
                      </td>
                      <td className="py-3 text-gray-400 text-sm">
                        {new Date(payment.createdAt).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Payments Tab */}
      {activeTab === 'payments' && payments && (
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white">All Payments</h3>
            <div className="flex items-center space-x-2 text-sm text-gray-400">
              <span>Total: {payments.pagination.total}</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-gray-400 text-sm border-b border-white/10">
                  <th className="pb-3">ID</th>
                  <th className="pb-3">Client</th>
                  <th className="pb-3">Amount</th>
                  <th className="pb-3">Currency</th>
                  <th className="pb-3">Network</th>
                  <th className="pb-3">Status</th>
                  <th className="pb-3">Tx Hash</th>
                  <th className="pb-3">Date</th>
                </tr>
              </thead>
              <tbody>
                {payments.payments.map((payment) => (
                  <tr key={payment.id} className="border-b border-white/5 hover:bg-white/5">
                    <td className="py-3 text-white font-mono text-xs">
                      {payment.id.slice(0, 8)}...
                    </td>
                    <td className="py-3 text-white font-mono text-sm">
                      {payment.clientId.slice(0, 12)}...
                    </td>
                    <td className="py-3 text-white font-semibold">
                      ${payment.usdAmount.toFixed(2)}
                    </td>
                    <td className="py-3">
                      <span className="px-2 py-1 bg-blue-500/20 text-blue-300 rounded text-xs font-medium">
                        {payment.currency}
                      </span>
                    </td>
                    <td className="py-3 text-gray-300 text-sm">{payment.network || '-'}</td>
                    <td className="py-3">
                      <StatusBadge status={payment.status} />
                    </td>
                    <td className="py-3 text-gray-400 font-mono text-xs">
                      {payment.txHash ? `${payment.txHash.slice(0, 10)}...` : '-'}
                    </td>
                    <td className="py-3 text-gray-400 text-sm">
                      {new Date(payment.createdAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Privacy Routes Tab */}
      {activeTab === 'privacy' && privacyRoutes && (
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold text-white">Privacy Routes</h3>
            <div className="flex items-center space-x-2 text-sm text-gray-400">
              <span>Total: {privacyRoutes.pagination.total}</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-gray-400 text-sm border-b border-white/10">
                  <th className="pb-3">Route ID</th>
                  <th className="pb-3">Source</th>
                  <th className="pb-3">Amount</th>
                  <th className="pb-3">Stage</th>
                  <th className="pb-3">Hops</th>
                  <th className="pb-3">Privacy Score</th>
                  <th className="pb-3">Date</th>
                </tr>
              </thead>
              <tbody>
                {privacyRoutes.privacyRoutes.map((route) => (
                  <tr key={route.id} className="border-b border-white/5 hover:bg-white/5">
                    <td className="py-3 text-white font-mono text-xs">
                      {route.id.slice(0, 8)}...
                    </td>
                    <td className="py-3">
                      <div className="text-white text-sm">{route.sourceChain}</div>
                      <div className="text-gray-400 text-xs font-mono">
                        {route.sourceTxHash.slice(0, 12)}...
                      </div>
                    </td>
                    <td className="py-3 text-white font-semibold">
                      {route.sourceAmount} {route.sourceCurrency}
                    </td>
                    <td className="py-3">
                      <StageBadge stage={route.stage} />
                    </td>
                    <td className="py-3 text-white">{route.hopCount}</td>
                    <td className="py-3">
                      {route.privacyScore ? (
                        <span className="text-green-400 font-semibold">
                          {parseFloat(route.privacyScore).toFixed(0)}/100
                        </span>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                    <td className="py-3 text-gray-400 text-sm">
                      {new Date(route.depositedAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function TabButton({ label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 rounded-lg font-medium transition-all whitespace-nowrap ${
        active
          ? 'bg-purple-600 text-white shadow-lg'
          : 'bg-slate-800/50 text-gray-300 hover:bg-slate-700/50'
      }`}
    >
      {label}
    </button>
  );
}

function StatCard({ label, value, icon, color }) {
  const colorClasses = {
    blue: 'from-blue-600 to-blue-700',
    green: 'from-green-600 to-green-700',
    purple: 'from-purple-600 to-purple-700',
    pink: 'from-pink-600 to-pink-700',
  };

  return (
    <div className={`bg-gradient-to-br ${colorClasses[color]} rounded-xl p-6 text-white shadow-lg`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm opacity-90">{label}</span>
        {icon}
      </div>
      <p className="text-3xl font-bold">{value}</p>
    </div>
  );
}

function WalletCard({ label, balance, address }) {
  return (
    <div className="bg-slate-700/30 rounded-lg p-4 border border-white/10">
      <p className="text-sm text-gray-400 mb-2">{label}</p>
      <p className="text-xl font-bold text-white mb-2">{balance}</p>
      <p className="text-xs text-gray-500 font-mono truncate">{address}</p>
    </div>
  );
}

function StatusBadge({ status }) {
  const styles = {
    confirmed: 'bg-green-500/20 text-green-300 border-green-500/50',
    pending: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50',
    failed: 'bg-red-500/20 text-red-300 border-red-500/50',
    privacy_routing: 'bg-purple-500/20 text-purple-300 border-purple-500/50',
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium border ${styles[status] || styles.pending}`}>
      {status}
    </span>
  );
}

function StageBadge({ stage }) {
  const styles = {
    completed: 'bg-green-500/20 text-green-300',
    failed: 'bg-red-500/20 text-red-300',
    mixing: 'bg-purple-500/20 text-purple-300',
    shielding: 'bg-blue-500/20 text-blue-300',
    unshielding: 'bg-yellow-500/20 text-yellow-300',
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${styles[stage] || 'bg-slate-500/20 text-slate-300'}`}>
      {stage}
    </span>
  );
}