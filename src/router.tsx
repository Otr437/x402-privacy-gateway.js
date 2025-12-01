import React, { useState, useEffect } from 'react';
import { Shield, Loader2, CheckCircle, AlertCircle, RefreshCw, ExternalLink, Clock, ArrowRight, Eye, Zap } from 'lucide-react';

const API_BASE = 'http://localhost:3402/api/v1';

export default function PrivacyRouterPortal() {
  const [activeTab, setActiveTab] = useState('initiate');
  const [clientId, setClientId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  // Initiate Route State
  const [routeForm, setRouteForm] = useState({
    amount: '',
    currency: 'usdc',
    sourceChain: 'base',
    sourceTxHash: '',
    destinationChain: 'base',
    destinationAddress: '',
  });
  const [initiatedRoute, setInitiatedRoute] = useState(null);
  
  // Track Route State
  const [trackRouteId, setTrackRouteId] = useState('');
  const [routeStatus, setRouteStatus] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(null);

  useEffect(() => {
    const savedClientId = localStorage.getItem('x402_client_id');
    if (savedClientId) {
      setClientId(savedClientId);
    } else {
      const newId = `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      setClientId(newId);
      localStorage.setItem('x402_client_id', newId);
    }
  }, []);

  useEffect(() => {
    return () => {
      if (refreshInterval) {
        clearInterval(refreshInterval);
      }
    };
  }, [refreshInterval]);

  useEffect(() => {
    if (autoRefresh && trackRouteId) {
      const interval = setInterval(() => {
        fetchRouteStatus(trackRouteId);
      }, 15000);
      setRefreshInterval(interval);
    } else if (refreshInterval) {
      clearInterval(refreshInterval);
      setRefreshInterval(null);
    }
  }, [autoRefresh, trackRouteId]);

  const initiateRoute = async () => {
    setLoading(true);
    setError('');
    setInitiatedRoute(null);

    try {
      const response = await fetch(`${API_BASE}/payments/privacy-route`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientId,
          amount: parseFloat(routeForm.amount),
          currency: routeForm.currency.toUpperCase(),
          sourceChain: routeForm.sourceChain,
          sourceTxHash: routeForm.sourceTxHash,
          destinationChain: routeForm.destinationChain,
          destinationAddress: routeForm.destinationAddress || undefined,
          resource: 'privacy-router-portal'
        })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to initiate privacy route');

      setInitiatedRoute(data);
      setTrackRouteId(data.routeId);
      setActiveTab('track');
      
      // Auto-fetch status after initiation
      setTimeout(() => {
        fetchRouteStatus(data.routeId);
      }, 2000);

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchRouteStatus = async (routeId) => {
    if (!routeId) routeId = trackRouteId;
    if (!routeId) return;

    try {
      const response = await fetch(`${API_BASE}/payments/privacy-route/${routeId}/status`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to fetch route status');
      setRouteStatus(data);
      
      // Stop auto-refresh if route is completed or failed
      if (data.status === 'completed' || data.status === 'failed') {
        setAutoRefresh(false);
      }
    } catch (err) {
      console.error('Status fetch error:', err);
      setError(err.message);
    }
  };

  const getStageProgress = (stage) => {
    const stages = ['deposited', 'converting', 'shielding', 'mixing', 'unshielding', 'delivering', 'completed'];
    const currentIndex = stages.indexOf(stage);
    return ((currentIndex + 1) / stages.length) * 100;
  };

  const getStageColor = (stage) => {
    const colors = {
      deposited: 'text-blue-400',
      converting: 'text-cyan-400',
      shielding: 'text-purple-400',
      mixing: 'text-pink-400',
      unshielding: 'text-yellow-400',
      delivering: 'text-orange-400',
      completed: 'text-green-400',
      failed: 'text-red-400'
    };
    return colors[stage] || 'text-gray-400';
  };

  const getStageIcon = (stage) => {
    if (stage === 'completed') return <CheckCircle className="w-6 h-6" />;
    if (stage === 'failed') return <AlertCircle className="w-6 h-6" />;
    return <Loader2 className="w-6 h-6 animate-spin" />;
  };

  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 via-pink-600 to-purple-600 rounded-2xl p-6 text-white mb-6 shadow-2xl">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center space-x-3 mb-2">
              <Shield className="w-10 h-10" />
              <h1 className="text-3xl font-bold">Privacy Router</h1>
            </div>
            <p className="text-purple-100 mb-4">
              Route payments through Zcash's shielded pool for enhanced privacy using zero-knowledge proofs
            </p>
            <div className="grid grid-cols-3 gap-4 text-sm">
              <div className="bg-white/10 rounded-lg p-3">
                <div className="text-purple-200 text-xs mb-1">Privacy Method</div>
                <div className="font-semibold">Zero-Knowledge Proofs</div>
              </div>
              <div className="bg-white/10 rounded-lg p-3">
                <div className="text-purple-200 text-xs mb-1">Mixing Delay</div>
                <div className="font-semibold">5-60 minutes</div>
              </div>
              <div className="bg-white/10 rounded-lg p-3">
                <div className="text-purple-200 text-xs mb-1">Multi-Hop</div>
                <div className="font-semibold">Optional</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-2 mb-6">
        <TabButton 
          label="Initiate Route" 
          active={activeTab === 'initiate'} 
          onClick={() => setActiveTab('initiate')}
          icon={<Zap className="w-4 h-4" />}
        />
        <TabButton 
          label="Track Route" 
          active={activeTab === 'track'} 
          onClick={() => setActiveTab('track')}
          icon={<Eye className="w-4 h-4" />}
        />
      </div>

      {/* Initiate Route Tab */}
      {activeTab === 'initiate' && (
        <div className="space-y-6">
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
            <h2 className="text-2xl font-bold text-white mb-6">Initiate Privacy Route</h2>

            <div className="bg-purple-900/30 rounded-lg p-4 border border-purple-500/30 mb-6">
              <div className="flex items-start space-x-3">
                <Shield className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                <div className="text-sm text-purple-200">
                  <p className="font-semibold mb-2">How Privacy Routing Works:</p>
                  <ol className="list-decimal list-inside space-y-1 text-xs">
                    <li>Your payment is sent to our deposit wallet on the source chain</li>
                    <li>We convert it to ZEC (if needed) and shield it to a z-address</li>
                    <li>The ZEC sits in the shielded pool with randomized mixing delay (5-60 min)</li>
                    <li>Optional: Route through intermediate z-address for multi-hop privacy</li>
                    <li>Unshield and deliver to destination (or convert back to original currency)</li>
                  </ol>
                  <p className="mt-2 text-purple-300 font-medium">
                    Result: Transaction graph analysis resistance + enhanced privacy score
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Amount (USD)</label>
                <input
                  type="number"
                  value={routeForm.amount}
                  onChange={(e) => setRouteForm({ ...routeForm, amount: e.target.value })}
                  placeholder="0.00"
                  step="0.01"
                  min="0.01"
                  className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Source Currency</label>
                  <select
                    value={routeForm.currency}
                    onChange={(e) => setRouteForm({ ...routeForm, currency: e.target.value })}
                    className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  >
                    <option value="usdc">USDC</option>
                    <option value="zec">Zcash (ZEC)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Source Chain</label>
                  <select
                    value={routeForm.sourceChain}
                    onChange={(e) => setRouteForm({ ...routeForm, sourceChain: e.target.value })}
                    className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  >
                    <option value="base">Base</option>
                    <option value="polygon">Polygon</option>
                    <option value="starknet">StarkNet</option>
                    {routeForm.currency === 'zec' && <option value="zcash">Zcash</option>}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Source Transaction Hash</label>
                <input
                  type="text"
                  value={routeForm.sourceTxHash}
                  onChange={(e) => setRouteForm({ ...routeForm, sourceTxHash: e.target.value })}
                  placeholder="0x... or txid"
                  className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono text-sm"
                />
                <p className="text-xs text-gray-400 mt-1">
                  Transaction hash of your payment to our deposit wallet
                </p>
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Destination Chain</label>
                  <select
                    value={routeForm.destinationChain}
                    onChange={(e) => setRouteForm({ ...routeForm, destinationChain: e.target.value })}
                    className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
                  >
                    <option value="base">Base</option>
                    <option value="polygon">Polygon</option>
                    <option value="starknet">StarkNet</option>
                    <option value="zcash">Zcash</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Destination Address (Optional)
                  </label>
                  <input
                    type="text"
                    value={routeForm.destinationAddress}
                    onChange={(e) => setRouteForm({ ...routeForm, destinationAddress: e.target.value })}
                    placeholder="Leave empty for default wallet"
                    className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono text-sm"
                  />
                </div>
              </div>

              {error && (
                <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-start space-x-3">
                  <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                  <p className="text-red-300 text-sm">{error}</p>
                </div>
              )}

              {initiatedRoute && (
                <div className="bg-green-500/20 border border-green-500/50 rounded-lg p-4">
                  <div className="flex items-start space-x-3">
                    <CheckCircle className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-green-300 font-semibold mb-2">Privacy Route Initiated!</p>
                      <p className="text-sm text-green-200 mb-2">Route ID: {initiatedRoute.routeId}</p>
                      <p className="text-xs text-green-200">
                        Your payment is now being processed through the privacy router. 
                        Switch to "Track Route" tab to monitor progress.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <button
                onClick={initiateRoute}
                disabled={!routeForm.amount || !routeForm.sourceTxHash || loading}
                className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-slate-600 disabled:to-slate-600 text-white font-semibold rounded-lg transition-all shadow-lg disabled:cursor-not-allowed flex items-center justify-center space-x-2"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Initiating Privacy Route...</span>
                  </>
                ) : (
                  <>
                    <Shield className="w-5 h-5" />
                    <span>Initiate Privacy Route</span>
                    <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Track Route Tab */}
      {activeTab === 'track' && (
        <div className="space-y-6">
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
            <h2 className="text-2xl font-bold text-white mb-6">Track Privacy Route</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Route ID</label>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={trackRouteId}
                    onChange={(e) => setTrackRouteId(e.target.value)}
                    placeholder="Enter route ID..."
                    className="flex-1 px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono text-sm"
                  />
                  <button
                    onClick={() => fetchRouteStatus()}
                    disabled={!trackRouteId}
                    className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-600 text-white font-semibold rounded-lg transition-colors disabled:cursor-not-allowed flex items-center space-x-2"
                  >
                    <RefreshCw className="w-5 h-5" />
                    <span>Track</span>
                  </button>
                </div>
              </div>

              {routeStatus && (
                <div className="space-y-4">
                  {/* Status Header */}
                  <div className="bg-gradient-to-r from-purple-900/50 to-pink-900/50 rounded-lg p-6 border border-purple-500/30">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <div className={`${getStageColor(routeStatus.status)}`}>
                          {getStageIcon(routeStatus.status)}
                        </div>
                        <div>
                          <h3 className="text-xl font-bold text-white capitalize">{routeStatus.status}</h3>
                          <p className="text-sm text-purple-200">Route ID: {routeStatus.routeId}</p>
                        </div>
                      </div>
                      <label className="flex items-center space-x-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={autoRefresh}
                          onChange={(e) => setAutoRefresh(e.target.checked)}
                          className="w-4 h-4 rounded border-purple-500 bg-slate-700 checked:bg-purple-600"
                        />
                        <span className="text-sm text-purple-200">Auto-refresh (15s)</span>
                      </label>
                    </div>

                    {/* Progress Bar */}
                    {routeStatus.status !== 'failed' && (
                      <div className="mb-4">
                        <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-gradient-to-r from-purple-500 to-pink-500 transition-all duration-500"
                            style={{ width: `${getStageProgress(routeStatus.status)}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {/* Privacy Score */}
                    {routeStatus.privacy.privacyScore && (
                      <div className="bg-green-900/30 rounded-lg p-4 border border-green-500/30">
                        <div className="flex items-center justify-between">
                          <span className="text-green-300 font-medium">Privacy Score:</span>
                          <span className="text-3xl font-bold text-green-400">
                            {routeStatus.privacy.privacyScore}/100
                          </span>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Privacy Features */}
                  <div className="bg-slate-700/30 rounded-lg p-4 border border-white/10">
                    <h4 className="font-semibold text-white mb-3">Privacy Features Active:</h4>
                    <div className="grid md:grid-cols-2 gap-3">
                      <FeatureBadge 
                        label="Shielded Pool" 
                        active={routeStatus.privacy.shieldedPoolUsed}
                      />
                      <FeatureBadge 
                        label="Zero-Knowledge Proofs" 
                        active={routeStatus.privacy.zeroKnowledgeProofs}
                      />
                      <FeatureBadge 
                        label="Mixing" 
                        active={routeStatus.privacy.mixingDelaySeconds > 0}
                        detail={routeStatus.privacy.mixingDelaySeconds ? `${routeStatus.privacy.mixingDelaySeconds}s` : null}
                      />
                      <FeatureBadge 
                        label="Multi-Hop" 
                        active={routeStatus.privacy.hopCount > 1}
                        detail={routeStatus.privacy.hopCount ? `${routeStatus.privacy.hopCount} hops` : null}
                      />
                    </div>
                  </div>

                  {/* Transaction Details */}
                  <div className="bg-slate-700/30 rounded-lg p-4 border border-white/10">
                    <h4 className="font-semibold text-white mb-3">Transaction Flow:</h4>
                    <div className="space-y-3">
                      <TransactionRow
                        label="Source"
                        chain={routeStatus.transactions.source.chain}
                        txHash={routeStatus.transactions.source.txHash}
                        status="completed"
                      />
                      {routeStatus.transactions.zecDeposit && (
                        <TransactionRow
                          label="ZEC Deposit"
                          chain="zcash"
                          txHash={routeStatus.transactions.zecDeposit}
                          status={routeStatus.status === 'deposited' || routeStatus.status === 'converting' ? 'pending' : 'completed'}
                        />
                      )}
                      {routeStatus.transactions.zecShielded && (
                        <TransactionRow
                          label="ZEC Shielded"
                          chain="zcash-private"
                          txHash={routeStatus.transactions.zecShielded}
                          status={routeStatus.status === 'shielding' ? 'pending' : routeStatus.status === 'mixing' || routeStatus.status === 'unshielding' || routeStatus.status === 'delivering' || routeStatus.status === 'completed' ? 'completed' : 'pending'}
                          isPrivate
                        />
                      )}
                      {routeStatus.transactions.zecIntermediate && (
                        <TransactionRow
                          label="ZEC Intermediate"
                          chain="zcash-private"
                          txHash={routeStatus.transactions.zecIntermediate}
                          status={routeStatus.status === 'mixing' ? 'pending' : 'completed'}
                          isPrivate
                        />
                      )}
                      {routeStatus.transactions.zecUnshield && (
                        <TransactionRow
                          label="ZEC Unshield"
                          chain="zcash"
                          txHash={routeStatus.transactions.zecUnshield}
                          status={routeStatus.status === 'unshielding' || routeStatus.status === 'delivering' ? 'pending' : routeStatus.status === 'completed' ? 'completed' : 'pending'}
                        />
                      )}
                      {routeStatus.transactions.destination && routeStatus.transactions.destination.txHash && (
                        <TransactionRow
                          label="Destination"
                          chain={routeStatus.transactions.destination.chain}
                          txHash={routeStatus.transactions.destination.txHash}
                          status={routeStatus.status === 'completed' ? 'completed' : 'pending'}
                        />
                      )}
                    </div>
                  </div>

                  {/* Payment Status */}
                  {routeStatus.paymentStatus && (
                    <div className="bg-slate-700/30 rounded-lg p-4 border border-white/10">
                      <div className="flex items-center justify-between">
                        <span className="text-gray-300">Payment Status:</span>
                        <span className={`px-3 py-1 rounded font-semibold text-sm ${
                          routeStatus.paymentStatus === 'confirmed' ? 'bg-green-500/20 text-green-300' :
                          routeStatus.paymentStatus === 'pending' ? 'bg-yellow-500/20 text-yellow-300' :
                          'bg-red-500/20 text-red-300'
                        }`}>
                          {routeStatus.paymentStatus}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Error Message */}
                  {routeStatus.errorMessage && (
                    <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4">
                      <div className="flex items-start space-x-3">
                        <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                        <div>
                          <p className="text-red-300 font-semibold mb-1">Error</p>
                          <p className="text-sm text-red-200">{routeStatus.errorMessage}</p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {error && !routeStatus && (
                <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-start space-x-3">
                  <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                  <p className="text-red-300 text-sm">{error}</p>
                </div>
              )}
            </div>
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
          ? 'bg-purple-600 text-white shadow-lg'
          : 'bg-slate-800/50 text-gray-300 hover:bg-slate-700/50'
      }`}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

function FeatureBadge({ label, active, detail }) {
  return (
    <div className={`flex items-center justify-between px-3 py-2 rounded-lg ${
      active ? 'bg-green-900/30 border border-green-500/30' : 'bg-slate-800/50 border border-slate-600'
    }`}>
      <span className={`text-sm font-medium ${active ? 'text-green-300' : 'text-gray-400'}`}>
        {label}
      </span>
      {detail && <span className="text-xs text-green-200">{detail}</span>}
    </div>
  );
}

function TransactionRow({ label, chain, txHash, status, isPrivate }) {
  const getExplorerUrl = (chain, hash) => {
    if (chain === 'base') return `https://basescan.org/tx/${hash}`;
    if (chain === 'polygon') return `https://polygonscan.com/tx/${hash}`;
    if (chain === 'starknet') return `https://starkscan.co/tx/${hash}`;
    if (chain === 'zcash' || chain === 'zcash-private') return `https://zcashblockexplorer.com/transactions/${hash}`;
    return null;
  };

  const explorerUrl = getExplorerUrl(chain, txHash);

  return (
    <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
      <div className="flex items-center space-x-3">
        <div className={`w-2 h-2 rounded-full ${
          status === 'completed' ? 'bg-green-400' : status === 'pending' ? 'bg-yellow-400 animate-pulse' : 'bg-gray-400'
        }`} />
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-white">{label}</span>
            {isPrivate && (
              <span className="px-2 py-0.5 bg-purple-500/20 text-purple-300 text-xs rounded">
                Private
              </span>
            )}
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs text-gray-400 font-mono">
              {txHash ? `${txHash.slice(0, 10)}...${txHash.slice(-8)}` : 'Pending...'}
            </span>
            {explorerUrl && txHash && (
              <a
                href={explorerUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:text-blue-300"
              >
                <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
        </div>
      </div>
      <span className="text-xs text-gray-500 capitalize">{chain}</span>
    </div>
  );
}