import React, { useState, useEffect } from 'react';
import { Wallet, Shield, TrendingUp, DollarSign, Activity, Settings, LogOut, User, Menu, X } from 'lucide-react';

const API_BASE = 'http://localhost:3402/api/v1';

// Main App Component
export default function X402App() {
  const [currentView, setCurrentView] = useState('home');
  const [authToken, setAuthToken] = useState(localStorage.getItem('x402_token'));
  const [user, setUser] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (authToken) {
      const userData = JSON.parse(localStorage.getItem('x402_user') || '{}');
      setUser(userData);
    }
  }, [authToken]);

  const checkHealth = async () => {
    try {
      const response = await fetch(`${API_BASE}/health`);
      const data = await response.json();
      setHealth(data);
    } catch (error) {
      console.error('Health check failed:', error);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('x402_token');
    localStorage.removeItem('x402_user');
    setAuthToken(null);
    setUser(null);
    setCurrentView('home');
  };

  const handleLogin = (token, userData) => {
    localStorage.setItem('x402_token', token);
    localStorage.setItem('x402_user', JSON.stringify(userData));
    setAuthToken(token);
    setUser(userData);
    setCurrentView('admin-dashboard');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <header className="bg-black/20 backdrop-blur-lg border-b border-white/10 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="lg:hidden text-white hover:text-purple-400 transition-colors"
              >
                {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
              <div className="flex items-center space-x-3">
                <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-white">X402 Payments</h1>
                  <p className="text-xs text-purple-300">Multi-Chain Privacy Protocol</p>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {health && (
                <div className="hidden sm:flex items-center space-x-2 px-3 py-1 bg-green-500/20 rounded-full">
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-xs text-green-300 font-medium">{health.status}</span>
                </div>
              )}
              
              {user ? (
                <div className="flex items-center space-x-3">
                  <div className="hidden sm:block text-right">
                    <p className="text-sm font-medium text-white">{user.username}</p>
                    <p className="text-xs text-purple-300">{user.role}</p>
                  </div>
                  <button
                    onClick={handleLogout}
                    className="p-2 bg-red-500/20 hover:bg-red-500/30 rounded-lg transition-colors"
                  >
                    <LogOut className="w-5 h-5 text-red-300" />
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setCurrentView('login')}
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition-colors"
                >
                  Admin Login
                </button>
              )}
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className={`${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0 fixed lg:static inset-y-0 left-0 z-40 w-64 bg-black/20 backdrop-blur-lg border-r border-white/10 transition-transform duration-300 mt-16 lg:mt-0`}>
          <nav className="p-4 space-y-2">
            <NavItem
              icon={<DollarSign className="w-5 h-5" />}
              label="Home"
              active={currentView === 'home'}
              onClick={() => setCurrentView('home')}
            />
            <NavItem
              icon={<Wallet className="w-5 h-5" />}
              label="Make Payment"
              active={currentView === 'payment'}
              onClick={() => setCurrentView('payment')}
            />
            <NavItem
              icon={<Shield className="w-5 h-5" />}
              label="Privacy Route"
              active={currentView === 'privacy'}
              onClick={() => setCurrentView('privacy')}
            />
            <NavItem
              icon={<TrendingUp className="w-5 h-5" />}
              label="Deferred Payments"
              active={currentView === 'deferred'}
              onClick={() => setCurrentView('deferred')}
            />
            <NavItem
              icon={<Activity className="w-5 h-5" />}
              label="Deposit Addresses"
              active={currentView === 'addresses'}
              onClick={() => setCurrentView('addresses')}
            />
            
            {authToken && (
              <>
                <div className="pt-4 mt-4 border-t border-white/10">
                  <p className="text-xs font-semibold text-purple-300 mb-2 px-3">ADMIN</p>
                </div>
                <NavItem
                  icon={<Activity className="w-5 h-5" />}
                  label="Dashboard"
                  active={currentView === 'admin-dashboard'}
                  onClick={() => setCurrentView('admin-dashboard')}
                />
                <NavItem
                  icon={<DollarSign className="w-5 h-5" />}
                  label="Payments"
                  active={currentView === 'admin-payments'}
                  onClick={() => setCurrentView('admin-payments')}
                />
                <NavItem
                  icon={<Shield className="w-5 h-5" />}
                  label="Privacy Routes"
                  active={currentView === 'admin-privacy'}
                  onClick={() => setCurrentView('admin-privacy')}
                />
              </>
            )}
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-4 lg:p-8 overflow-y-auto min-h-screen">
          {currentView === 'home' && <HomeView health={health} />}
          {currentView === 'payment' && <PaymentView />}
          {currentView === 'privacy' && <PrivacyRouteView />}
          {currentView === 'deferred' && <DeferredPaymentView />}
          {currentView === 'addresses' && <DepositAddressesView />}
          {currentView === 'login' && <LoginView onLogin={handleLogin} />}
          {currentView === 'admin-dashboard' && authToken && <AdminDashboard token={authToken} />}
          {currentView === 'admin-payments' && authToken && <AdminPayments token={authToken} />}
          {currentView === 'admin-privacy' && authToken && <AdminPrivacyRoutes token={authToken} />}
        </main>
      </div>
    </div>
  );
}

// Navigation Item Component
function NavItem({ icon, label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-all ${
        active
          ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/50'
          : 'text-gray-300 hover:bg-white/5 hover:text-white'
      }`}
    >
      {icon}
      <span className="font-medium">{label}</span>
    </button>
  );
}

// Home View
function HomeView({ health }) {
  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-purple-600 to-pink-600 rounded-2xl p-8 text-white shadow-2xl">
        <h2 className="text-3xl font-bold mb-4">Welcome to X402 Payment System</h2>
        <p className="text-purple-100 text-lg mb-6">
          Multi-chain cryptocurrency payment gateway with privacy-first architecture
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
            <DollarSign className="w-8 h-8 mb-2" />
            <h3 className="font-semibold mb-1">USDC Payments</h3>
            <p className="text-sm text-purple-100">Base, Polygon, StarkNet</p>
          </div>
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
            <Shield className="w-8 h-8 mb-2" />
            <h3 className="font-semibold mb-1">Privacy Coins</h3>
            <p className="text-sm text-purple-100">Zcash & Monero</p>
          </div>
          <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4">
            <Activity className="w-8 h-8 mb-2" />
            <h3 className="font-semibold mb-1">Privacy Router</h3>
            <p className="text-sm text-purple-100">Zcash Shielded Pool</p>
          </div>
        </div>
      </div>

      {health && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Protocol"
            value={health.protocol.toUpperCase()}
            icon={<Shield className="w-6 h-6 text-purple-400" />}
          />
          <StatCard
            label="Status"
            value={health.status}
            icon={<Activity className="w-6 h-6 text-green-400" />}
          />
          <StatCard
            label="Features"
            value={health.features.length}
            icon={<TrendingUp className="w-6 h-6 text-blue-400" />}
          />
          <StatCard
            label="Privacy Queue"
            value={health.privacyRouter.queueSize}
            icon={<Wallet className="w-6 h-6 text-pink-400" />}
          />
        </div>
      )}

      {health && (
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
          <h3 className="text-xl font-bold text-white mb-4">System Status</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatusIndicator label="Database" status={health.system.database} />
            <StatusIndicator label="Redis" status={health.system.redis} />
            <StatusIndicator label="Base RPC" status={health.system.base_rpc} />
            <StatusIndicator label="Polygon RPC" status={health.system.polygon_rpc} />
            <StatusIndicator label="StarkNet RPC" status={health.system.starknet_rpc} />
            <StatusIndicator label="Zcash RPC" status={health.system.zcash_rpc} />
            <StatusIndicator label="Monero RPC" status={health.system.monero_rpc} />
            <StatusIndicator 
              label="Privacy Router" 
              status={health.privacyRouter.enabled ? 'enabled' : 'disabled'} 
            />
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon }) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <div className="flex items-center justify-between mb-2">
        <span className="text-gray-400 text-sm">{label}</span>
        {icon}
      </div>
      <p className="text-2xl font-bold text-white">{value}</p>
    </div>
  );
}

function StatusIndicator({ label, status }) {
  const isConnected = status === 'connected' || status === 'enabled';
  return (
    <div className="flex items-center space-x-2">
      <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`}></div>
      <span className="text-sm text-gray-300">{label}</span>
    </div>
  );
}

// Payment View (Simplified - will be in separate artifact)
function PaymentView() {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <h2 className="text-2xl font-bold text-white mb-4">Make Payment</h2>
      <p className="text-gray-400">See Payment Portal artifact for full functionality</p>
    </div>
  );
}

// Privacy Route View (Simplified)
function PrivacyRouteView() {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <h2 className="text-2xl font-bold text-white mb-4">Privacy Router</h2>
      <p className="text-gray-400">See Privacy Portal artifact for full functionality</p>
    </div>
  );
}

// Deferred Payment View (Simplified)
function DeferredPaymentView() {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <h2 className="text-2xl font-bold text-white mb-4">Deferred Payments</h2>
      <p className="text-gray-400">See Deferred Portal artifact for full functionality</p>
    </div>
  );
}

// Deposit Addresses View (Simplified)
function DepositAddressesView() {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <h2 className="text-2xl font-bold text-white mb-4">Deposit Addresses</h2>
      <p className="text-gray-400">See Deposit Info artifact for full functionality</p>
    </div>
  );
}

// Login View (Simplified)
function LoginView({ onLogin }) {
  return (
    <div className="max-w-md mx-auto bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <h2 className="text-2xl font-bold text-white mb-4">Admin Login</h2>
      <p className="text-gray-400">See Admin Portal artifact for full functionality</p>
    </div>
  );
}

// Admin Dashboard (Simplified)
function AdminDashboard({ token }) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <h2 className="text-2xl font-bold text-white mb-4">Admin Dashboard</h2>
      <p className="text-gray-400">See Admin Dashboard artifact for full functionality</p>
    </div>
  );
}

// Admin Payments (Simplified)
function AdminPayments({ token }) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <h2 className="text-2xl font-bold text-white mb-4">Payment Management</h2>
      <p className="text-gray-400">See Admin Dashboard artifact for full functionality</p>
    </div>
  );
}

// Admin Privacy Routes (Simplified)
function AdminPrivacyRoutes({ token }) {
  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10">
      <h2 className="text-2xl font-bold text-white mb-4">Privacy Routes</h2>
      <p className="text-gray-400">See Admin Dashboard artifact for full functionality</p>
    </div>
  );
}