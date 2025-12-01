import React, { useState, useEffect } from 'react';
import { Clock, DollarSign, Loader2, CheckCircle, AlertCircle, RefreshCw, Send, TrendingUp, Calendar } from 'lucide-react';

const API_BASE = 'http://localhost:3402/api/v1';

export default function DeferredPaymentsPortal() {
  const [activeTab, setActiveTab] = useState('balance');
  const [clientId, setClientId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Balance State
  const [balance, setBalance] = useState(null);
  const [balanceLoading, setBalanceLoading] = useState(false);

  // Authorization State
  const [authAmount, setAuthAmount] = useState('');
  const [authorization, setAuthorization] = useState(null);

  // Settlement State
  const [settleTxHash, setSettleTxHash] = useState('');
  const [settleNetwork, setSettleNetwork] = useState('base');
  const [settleResult, setSettleResult] = useState(null);

  useEffect(() => {
    const savedClientId = localStorage.getItem('x402_client_id');
    if (savedClientId) {
      setClientId(savedClientId);
      fetchBalance(savedClientId);
    } else {
      const newId = `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      setClientId(newId);
      localStorage.setItem('x402_client_id', newId);
    }
  }, []);

  const fetchBalance = async (id = clientId) => {
    if (!id) return;
    setBalanceLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE}/payments/deferred/balance/${id}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to fetch balance');
      setBalance(data);
    } catch (err) {
      if (err.message.includes('404')) {
        setBalance({ balance: 0, paymentCount: 0, payments: [], clientId: id });
      } else {
        setError(err.message);
      }
    } finally {
      setBalanceLoading(false);
    }
  };

  const generateAuthorization = async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    setAuthorization(null);

    try {
      const response = await fetch(`${API_BASE}/payments/deferred/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientId,
          amount: parseFloat(authAmount)
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to generate authorization');
      
      setAuthorization(data);
      setSuccess('Authorization generated successfully! Use this for deferred payments.');
      setAuthAmount('');
      
      // Refresh balance
      setTimeout(() => fetchBalance(), 1000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const settlePayments = async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    setSettleResult(null);

    try {
      const response = await fetch(`${API_BASE}/payments/deferred/settle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientId,
          paymentTxHash: settleTxHash,
          network: settleNetwork
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to settle payments');
      
      setSettleResult(data);
      setSuccess(`Successfully settled ${data.paymentCount} payments totaling $${data.totalAmount}!`);
      setSettleTxHash('');
      
      // Refresh balance
      setTimeout(() => fetchBalance(), 1000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 via-cyan-600 to-blue-600 rounded-2xl p-6 text-white mb-6 shadow-2xl">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center space-x-3 mb-2">
              <Clock className="w-10 h-10" />
              <h1 className="text-3xl font-bold">Deferred Payments</h1>
            </div>
            <p className="text-blue-100 mb-4">
              Batch multiple payments and settle them together with a single USDC transaction
            </p>
            <div className="grid grid-cols-3 gap-4 text-sm">
              <div className="bg-white/10 rounded-lg p-3">
                <div className="text-blue-200 text-xs mb-1">Settlement</div>
                <div className="font-semibold">Batch</div>
              </div>
              <div className="bg-white/10 rounded-lg p-3">
                <div className="text-blue-200 text-xs mb-1">Currency</div>
                <div className="font-semibold">USDC Only</div>
              </div>
              <div className="bg-white/10 rounded-lg p-3">
                <div className="text-blue-200 text-xs mb-1">Networks</div>
                <div className="font-semibold">Base, Polygon, StarkNet</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Client ID Display */}
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-white/10 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <span className="text-sm text-gray-400">Your Client ID:</span>
            <p className="text-white font-mono text-sm mt-1">{clientId}</p>
          </div>
          <button
            onClick={() => fetchBalance()}
            disabled={balanceLoading}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white rounded-lg transition-colors flex items-center space-x-2"
          >
            <RefreshCw className={`w-4 h-4 ${balanceLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-2 mb-6">
        <TabButton 
          label="Balance & History" 
          active={activeTab === 'balance'} 
          onClick={() => setActiveTab('balance')}
          icon={<DollarSign className="w-4 h-4" />}
        />
        <TabButton 
          label="Authorize Payment" 
          active={activeTab === 'authorize'} 
          onClick={() => setActiveTab('authorize')}
          icon={<Calendar className="w-4 h-4" />}
        />
        <TabButton 
          label="Settle Payments" 
          active={activeTab === 'settle'} 
          onClick={() => setActiveTab('settle')}
          icon={<Send className="w-4 h-4" />}
        />
      </div>

      {/* Alert Messages */}
      {error && (
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-start space-x-3 mb-6">
          <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-red-300 text-sm font-semibold">Error</p>
            <p className="text-red-200 text-sm">{error}</p>
          </div>
        </div>
      )}

      {success && (
        <div className="bg-green-500/20 border border-green-500/50 rounded-lg p-4 flex items-start space-x-3 mb-6">
          <CheckCircle className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-green-300 text-sm font-semibold">Success</p>
            <p className="text-green-200 text-sm">{success}</p>
          </div>
        </div>
      )}

      {/* Balance & History Tab */}
      {activeTab === 'balance' && (
        <div className="space-y-6">
          {/* Balance Card */}
          <div className="bg-gradient-to-br from-blue-900/50 to-cyan-900/50 rounded-xl p-6 border border-blue-500/30 shadow-xl">
            <h2 className="text-xl font-bold text-white mb-4">Current Balance</h2>
            {balanceLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
              </div>
            ) : balance ? (
              <>
                <div className="mb-6">
                  <p className="text-sm text-blue-200 mb-2">Outstanding Amount:</p>
                  <p className="text-5xl font-bold text-white mb-2">${balance.balance.toFixed(2)}</p>
                  <p className="text-sm text-blue-300">
                    {balance.paymentCount} {balance.paymentCount === 1 ? 'payment' : 'payments'} pending settlement
                  </p>
                </div>

                {balance.balance > 0 && (
                  <div className="bg-blue-900/30 rounded-lg p-4 border border-blue-500/30">
                    <div className="flex items-start space-x-2">
                      <AlertCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                      <div className="text-sm text-blue-200">
                        <p className="font-semibold mb-1">Settlement Due</p>
                        <p>
                          Send exactly <span className="font-bold text-white">${balance.balance.toFixed(2)} USDC</span> to 
                          settle all pending payments on Base, Polygon, or StarkNet
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <p className="text-gray-400">No balance information available</p>
            )}
          </div>

          {/* Payment History */}
          {balance && balance.payments && balance.payments.length > 0 && (
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
              <h3 className="text-xl font-bold text-white mb-4">Payment History</h3>
              <div className="space-y-3">
                {balance.payments.map((payment, idx) => (
                  <div key={idx} className="bg-slate-700/30 rounded-lg p-4 border border-white/10">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-semibold">${payment.amount.toFixed(2)}</span>
                      <span className="px-2 py-1 bg-yellow-500/20 text-yellow-300 text-xs rounded">
                        Pending
                      </span>
                    </div>
                    {payment.resource && (
                      <p className="text-sm text-gray-400 mb-1">Resource: {payment.resource}</p>
                    )}
                    <p className="text-xs text-gray-500">
                      {new Date(payment.createdAt).toLocaleString()}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {balance && balance.payments && balance.payments.length === 0 && (
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-8 border border-white/10 text-center">
              <TrendingUp className="w-12 h-12 text-gray-500 mx-auto mb-3" />
              <p className="text-gray-400">No deferred payments yet</p>
              <p className="text-sm text-gray-500 mt-1">
                Generate payment authorizations to start using deferred payments
              </p>
            </div>
          )}
        </div>
      )}

      {/* Authorize Payment Tab */}
      {activeTab === 'authorize' && (
        <div className="space-y-6">
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
            <h2 className="text-2xl font-bold text-white mb-6">Generate Payment Authorization</h2>

            <div className="bg-blue-900/30 rounded-lg p-4 border border-blue-500/30 mb-6">
              <div className="flex items-start space-x-3">
                <Clock className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div className="text-sm text-blue-200">
                  <p className="font-semibold mb-2">How Deferred Payments Work:</p>
                  <ol className="list-decimal list-inside space-y-1 text-xs">
                    <li>Generate an authorization code for a specific amount</li>
                    <li>Use the authorization to access paid resources immediately</li>
                    <li>Your balance accumulates with each authorized payment</li>
                    <li>Settle all payments at once with a single USDC transaction</li>
                  </ol>
                  <p className="mt-2 text-blue-300 font-medium">
                    Benefit: Reduce transaction fees by batching multiple payments
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Amount (USD)
                </label>
                <input
                  type="number"
                  value={authAmount}
                  onChange={(e) => setAuthAmount(e.target.value)}
                  placeholder="0.00"
                  step="0.01"
                  min="1.00"
                  max="10000.00"
                  className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <p className="text-xs text-gray-400 mt-1">
                  Min: $1.00 | Max: $10,000.00
                </p>
              </div>

              {authorization && (
                <div className="bg-green-900/30 rounded-lg p-4 border border-green-500/30">
                  <div className="flex items-start space-x-3 mb-3">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-green-300 font-semibold mb-1">Authorization Generated</p>
                      <p className="text-sm text-green-200 mb-3">
                        Amount: ${authorization.amount} | Expires in: {authorization.expiresIn}s
                      </p>
                    </div>
                  </div>
                  <div className="bg-slate-900/50 rounded-lg p-3">
                    <div className="text-xs text-green-300 mb-1">Authorization Code:</div>
                    <code className="text-white font-mono text-xs break-all block">
                      {authorization.authorization}
                    </code>
                  </div>
                  <p className="text-xs text-green-200 mt-3">
                    Use this authorization in the Payment-Authorization header for API requests
                  </p>
                </div>
              )}

              <button
                onClick={generateAuthorization}
                disabled={!authAmount || parseFloat(authAmount) < 1 || parseFloat(authAmount) > 10000 || loading}
                className="w-full py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 disabled:from-slate-600 disabled:to-slate-600 text-white font-semibold rounded-lg transition-all shadow-lg disabled:cursor-not-allowed flex items-center justify-center space-x-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Generating...</span>
                  </>
                ) : (
                  <>
                    <Calendar className="w-5 h-5" />
                    <span>Generate Authorization</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Settle Payments Tab */}
      {activeTab === 'settle' && (
        <div className="space-y-6">
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
            <h2 className="text-2xl font-bold text-white mb-6">Settle All Payments</h2>

            {balance && balance.balance > 0 ? (
              <>
                <div className="bg-yellow-900/30 rounded-lg p-4 border border-yellow-500/30 mb-6">
                  <div className="flex items-start space-x-3">
                    <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                    <div className="text-sm text-yellow-200">
                      <p className="font-semibold mb-2">Settlement Required</p>
                      <p>
                        You have <span className="font-bold text-white">${balance.balance.toFixed(2)}</span> in 
                        outstanding deferred payments across <span className="font-bold text-white">{balance.paymentCount}</span> transaction(s).
                      </p>
                      <p className="mt-2">
                        Send exactly this amount in USDC to settle all pending payments.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Settlement Network
                    </label>
                    <div className="grid grid-cols-3 gap-3">
                      <NetworkButton 
                        label="Base" 
                        selected={settleNetwork === 'base'} 
                        onClick={() => setSettleNetwork('base')} 
                      />
                      <NetworkButton 
                        label="Polygon" 
                        selected={settleNetwork === 'polygon'} 
                        onClick={() => setSettleNetwork('polygon')} 
                      />
                      <NetworkButton 
                        label="StarkNet" 
                        selected={settleNetwork === 'starknet'} 
                        onClick={() => setSettleNetwork('starknet')} 
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Settlement Transaction Hash
                    </label>
                    <input
                      type="text"
                      value={settleTxHash}
                      onChange={(e) => setSettleTxHash(e.target.value)}
                      placeholder="0x... or txid"
                      className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm"
                    />
                    <p className="text-xs text-gray-400 mt-1">
                      Transaction hash of your ${balance.balance.toFixed(2)} USDC payment
                    </p>
                  </div>

                  {settleResult && (
                    <div className="bg-green-900/30 rounded-lg p-4 border border-green-500/30">
                      <div className="flex items-start space-x-3">
                        <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                        <div>
                          <p className="text-green-300 font-semibold mb-2">Settlement Confirmed!</p>
                          <div className="text-sm text-green-200 space-y-1">
                            <p>Payments Settled: {settleResult.paymentCount}</p>
                            <p>Total Amount: ${settleResult.totalAmount}</p>
                            <p>Settlement Tx: {settleResult.settlementTx.slice(0, 20)}...</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  <button
                    onClick={settlePayments}
                    disabled={!settleTxHash || loading}
                    className="w-full py-3 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 disabled:from-slate-600 disabled:to-slate-600 text-white font-semibold rounded-lg transition-all shadow-lg disabled:cursor-not-allowed flex items-center justify-center space-x-2"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-5 h-5 animate-spin" />
                        <span>Settling...</span>
                      </>
                    ) : (
                      <>
                        <Send className="w-5 h-5" />
                        <span>Settle ${balance.balance.toFixed(2)}</span>
                      </>
                    )}
                  </button>
                </div>
              </>
            ) : (
              <div className="bg-slate-700/30 rounded-lg p-8 border border-white/10 text-center">
                <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-3" />
                <p className="text-white font-semibold mb-2">No Outstanding Payments</p>
                <p className="text-sm text-gray-400">
                  You don't have any deferred payments to settle
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function TabButton({ label, active, onClick, icon }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 rounded-lg font-medium transition-all flex items-center space-x-2 ${
        active
          ? 'bg-blue-600 text-white shadow-lg'
          : 'bg-slate-800/50 text-gray-300 hover:bg-slate-700/50'
      }`}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

function NetworkButton({ label, selected, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`py-2 px-4 rounded-lg text-sm font-medium transition-all ${
        selected
          ? 'bg-blue-600 text-white shadow-lg'
          : 'bg-slate-700/50 text-gray-300 hover:bg-slate-700'
      }`}
    >
      {label}
    </button>
  );
}