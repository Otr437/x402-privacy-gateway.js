import React, { useState, useEffect } from 'react';
import { Wallet, Copy, CheckCircle, AlertCircle, Loader2, ExternalLink, ArrowRight, RefreshCw, Shield, Clock, Zap } from 'lucide-react';

const API_BASE = 'http://localhost:3402/api/v1';

export default function PaymentPortal() {
  const [step, setStep] = useState(1);
  const [amount, setAmount] = useState('');
  const [currency, setCurrency] = useState('usdc');
  const [network, setNetwork] = useState('base');
  const [clientId, setClientId] = useState('');
  const [paymentRequest, setPaymentRequest] = useState(null);
  const [rates, setRates] = useState(null);
  const [txHash, setTxHash] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [depositAddresses, setDepositAddresses] = useState(null);
  const [balances, setBalances] = useState(null);
  const [copied, setCopied] = useState(false);
  const [autoCheckInterval, setAutoCheckInterval] = useState(null);
  const [checkAttempts, setCheckAttempts] = useState(0);
  const [paymentType, setPaymentType] = useState('immediate');
  const [usePrivacyRoute, setUsePrivacyRoute] = useState(false);
  const [privacyRouteId, setPrivacyRouteId] = useState(null);
  const [deferredAuth, setDeferredAuth] = useState(null);

  useEffect(() => {
    initializePortal();
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
      if (autoCheckInterval) {
        clearInterval(autoCheckInterval);
      }
    };
  }, [autoCheckInterval]);

  const initializePortal = async () => {
    try {
      const [ratesData, addressesData, balancesData] = await Promise.all([
        fetch(`${API_BASE}/rates`).then(r => r.json()),
        fetch(`${API_BASE}/deposit-addresses`).then(r => r.json()),
        fetch(`${API_BASE}/wallet/balance`).then(r => r.json())
      ]);
      setRates(ratesData);
      setDepositAddresses(addressesData);
      setBalances(balancesData);
    } catch (err) {
      console.error('Initialization failed:', err);
      setError('Failed to initialize payment portal. Please refresh.');
    }
  };

  const generatePaymentRequest = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE}/payments/generate-request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amount: parseFloat(amount),
          clientId,
          resource: 'payment-portal',
          currencies: [currency],
          allowDeferred: paymentType === 'deferred'
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to generate payment request');
      setPaymentRequest(data);
      
      if (paymentType === 'deferred') {
        await generateDeferredAuth();
      }
      
      setStep(2);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const generateDeferredAuth = async () => {
    try {
      const response = await fetch(`${API_BASE}/payments/deferred/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientId,
          amount: parseFloat(amount)
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to generate deferred authorization');
      setDeferredAuth(data);
    } catch (err) {
      console.error('Deferred auth error:', err);
    }
  };

  const verifyPayment = async () => {
    setVerifying(true);
    setError('');
    setVerificationResult(null);
    setCheckAttempts(prev => prev + 1);

    try {
      const response = await fetch(`${API_BASE}/payments/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          currency: currency.toUpperCase(),
          proof: txHash,
          amount: parseFloat(amount),
          clientId,
          network: currency === 'usdc' ? network : undefined,
          type: currency === 'zec' ? (network === 'shielded' ? 'shielded' : 'transparent') : undefined
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Verification failed');
      
      setVerificationResult(data);
      
      if (data.verified) {
        if (autoCheckInterval) {
          clearInterval(autoCheckInterval);
          setAutoCheckInterval(null);
        }
        
        if (usePrivacyRoute && (currency === 'usdc' || currency === 'zec')) {
          await initiatePrivacyRoute(txHash);
        } else {
          setStep(3);
        }
      } else {
        if (checkAttempts < 20 && !autoCheckInterval) {
          const interval = setInterval(() => {
            verifyPayment();
          }, 10000);
          setAutoCheckInterval(interval);
        }
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setVerifying(false);
    }
  };

  const initiatePrivacyRoute = async (sourceTx) => {
    try {
      const response = await fetch(`${API_BASE}/payments/privacy-route`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          clientId,
          amount: parseFloat(amount),
          currency: currency.toUpperCase(),
          sourceChain: network,
          sourceTxHash: sourceTx,
          destinationChain: network,
          destinationAddress: getDepositAddress(),
          resource: 'payment-portal'
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Privacy routing failed');
      setPrivacyRouteId(data.routeId);
      setStep(3);
    } catch (err) {
      setError(err.message);
      setStep(3);
    }
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Copy failed:', err);
    }
  };

  const getDepositAddress = () => {
    if (!depositAddresses) return '';
    if (currency === 'usdc') {
      if (network === 'starknet') {
        return depositAddresses.depositAddresses.usdc.starknet.address;
      } else if (network === 'polygon') {
        return depositAddresses.depositAddresses.usdc.polygon.address;
      } else {
        return depositAddresses.depositAddresses.usdc.base.address;
      }
    }
    if (currency === 'zec') {
      return network === 'shielded' 
        ? depositAddresses.depositAddresses.zec.shielded.address 
        : depositAddresses.depositAddresses.zec.transparent.address;
    }
    if (currency === 'xmr') {
      return depositAddresses.depositAddresses.xmr.address;
    }
    return '';
  };

  const getPaymentAmount = () => {
    if (!paymentRequest || !rates) return '0';
    if (currency === 'usdc') {
      return paymentRequest.payment.amount.usdc.toFixed(6);
    } else if (currency === 'zec') {
      return paymentRequest.payment.amount.zec.toFixed(8);
    } else if (currency === 'xmr') {
      return paymentRequest.payment.amount.xmr.toFixed(12);
    }
    return '0';
  };

  const getExplorerUrl = () => {
    if (!txHash) return '';
    if (currency === 'usdc') {
      if (network === 'base') return `https://basescan.org/tx/${txHash}`;
      if (network === 'polygon') return `https://polygonscan.com/tx/${txHash}`;
      if (network === 'starknet') return `https://starkscan.co/tx/${txHash}`;
    }
    if (currency === 'zec') return `https://zcashblockexplorer.com/transactions/${txHash}`;
    if (currency === 'xmr') return `https://xmrchain.net/search?value=${txHash}`;
    return '';
  };

  const getBalanceForCurrency = () => {
    if (!balances) return null;
    if (currency === 'usdc') {
      const wallet = balances.depositWallets.usdc.find(w => w.network === network);
      return wallet ? parseFloat(wallet.balance).toFixed(6) : '0.00';
    }
    if (currency === 'zec') {
      return network === 'shielded' 
        ? parseFloat(balances.depositWallets.zec.shielded.balance).toFixed(8)
        : parseFloat(balances.depositWallets.zec.transparent.balance).toFixed(8);
    }
    if (currency === 'xmr') {
      return balances.depositWallets.xmr.balance.toFixed(12);
    }
    return null;
  };

  const resetForm = () => {
    setStep(1);
    setPaymentRequest(null);
    setTxHash('');
    setVerificationResult(null);
    setAmount('');
    setError('');
    setCheckAttempts(0);
    setPrivacyRouteId(null);
    setDeferredAuth(null);
    if (autoCheckInterval) {
      clearInterval(autoCheckInterval);
      setAutoCheckInterval(null);
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="bg-gradient-to-r from-purple-600 to-pink-600 rounded-2xl p-6 text-white mb-6 shadow-2xl">
        <h1 className="text-3xl font-bold mb-2">Payment Portal</h1>
        <p className="text-purple-100">Multi-chain cryptocurrency payments with real on-chain verification</p>
        {balances && (
          <div className="mt-4 grid grid-cols-3 gap-4 text-sm">
            <div className="bg-white/10 rounded-lg p-2">
              <div className="text-purple-200 text-xs">USDC Balance</div>
              <div className="font-semibold">
                {balances.depositWallets.usdc.reduce((sum, w) => sum + parseFloat(w.balance), 0).toFixed(2)}
              </div>
            </div>
            <div className="bg-white/10 rounded-lg p-2">
              <div className="text-purple-200 text-xs">ZEC Balance</div>
              <div className="font-semibold">{balances.depositWallets.zec.total}</div>
            </div>
            <div className="bg-white/10 rounded-lg p-2">
              <div className="text-purple-200 text-xs">XMR Balance</div>
              <div className="font-semibold">{balances.depositWallets.xmr.balance.toFixed(4)}</div>
            </div>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between mb-8">
        <StepIndicator number={1} label="Configure" active={step >= 1} completed={step > 1} />
        <div className={`flex-1 h-1 mx-2 ${step > 1 ? 'bg-purple-600' : 'bg-slate-700'}`}></div>
        <StepIndicator number={2} label="Send Payment" active={step >= 2} completed={step > 2} />
        <div className={`flex-1 h-1 mx-2 ${step > 2 ? 'bg-purple-600' : 'bg-slate-700'}`}></div>
        <StepIndicator number={3} label="Confirmed" active={step >= 3} completed={step > 3} />
      </div>

      {step === 1 && (
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
          <h2 className="text-2xl font-bold text-white mb-6">Configure Payment</h2>
          
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Amount (USD)</label>
              <input
                type="number"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="0.00"
                step="0.01"
                min="0.01"
                className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Payment Type</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={() => setPaymentType('immediate')}
                  className={`py-3 px-4 rounded-lg font-medium transition-all flex items-center justify-center space-x-2 ${
                    paymentType === 'immediate'
                      ? 'bg-purple-600 text-white shadow-lg'
                      : 'bg-slate-700/50 text-gray-300 hover:bg-slate-700'
                  }`}
                >
                  <Zap className="w-4 h-4" />
                  <span>Immediate</span>
                </button>
                <button
                  onClick={() => {
                    setPaymentType('deferred');
                    setCurrency('usdc');
                  }}
                  className={`py-3 px-4 rounded-lg font-medium transition-all flex items-center justify-center space-x-2 ${
                    paymentType === 'deferred'
                      ? 'bg-purple-600 text-white shadow-lg'
                      : 'bg-slate-700/50 text-gray-300 hover:bg-slate-700'
                  }`}
                >
                  <Clock className="w-4 h-4" />
                  <span>Deferred</span>
                </button>
              </div>
              {paymentType === 'deferred' && (
                <p className="text-xs text-gray-400 mt-2">Batch settlement - USDC only</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Payment Currency</label>
              <div className="grid grid-cols-3 gap-3">
                <CurrencyButton
                  currency="usdc"
                  label="USDC"
                  selected={currency === 'usdc'}
                  onClick={() => {
                    setCurrency('usdc');
                    setNetwork('base');
                  }}
                  disabled={false}
                />
                <CurrencyButton
                  currency="zec"
                  label="Zcash"
                  selected={currency === 'zec'}
                  onClick={() => {
                    if (paymentType === 'immediate') {
                      setCurrency('zec');
                      setNetwork('shielded');
                    }
                  }}
                  disabled={paymentType === 'deferred'}
                />
                <CurrencyButton
                  currency="xmr"
                  label="Monero"
                  selected={currency === 'xmr'}
                  onClick={() => {
                    if (paymentType === 'immediate') {
                      setCurrency('xmr');
                    }
                  }}
                  disabled={paymentType === 'deferred'}
                />
              </div>
            </div>

            {currency === 'usdc' && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Network</label>
                <div className="grid grid-cols-3 gap-3">
                  <NetworkButton label="Base" selected={network === 'base'} onClick={() => setNetwork('base')} />
                  <NetworkButton label="Polygon" selected={network === 'polygon'} onClick={() => setNetwork('polygon')} />
                  <NetworkButton label="StarkNet" selected={network === 'starknet'} onClick={() => setNetwork('starknet')} />
                </div>
              </div>
            )}

            {currency === 'zec' && (
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Address Type</label>
                <div className="grid grid-cols-2 gap-3">
                  <NetworkButton 
                    label="Shielded (Private)" 
                    selected={network === 'shielded'} 
                    onClick={() => setNetwork('shielded')} 
                  />
                  <NetworkButton 
                    label="Transparent" 
                    selected={network === 'transparent'} 
                    onClick={() => setNetwork('transparent')} 
                  />
                </div>
              </div>
            )}

            {paymentType === 'immediate' && (currency === 'usdc' || currency === 'zec') && (
              <div className="bg-purple-900/30 rounded-lg p-4 border border-purple-500/30">
                <label className="flex items-center space-x-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={usePrivacyRoute}
                    onChange={(e) => setUsePrivacyRoute(e.target.checked)}
                    className="w-5 h-5 rounded border-purple-500 bg-slate-700 checked:bg-purple-600"
                  />
                  <div className="flex items-center space-x-2">
                    <Shield className="w-5 h-5 text-purple-400" />
                    <span className="text-white font-medium">Route through Zcash Privacy Pool</span>
                  </div>
                </label>
                <p className="text-xs text-purple-300 mt-2 ml-8">
                  Enhanced privacy using zero-knowledge proofs and mixing delays
                </p>
              </div>
            )}

            {rates && amount && parseFloat(amount) > 0 && (
              <div className="bg-purple-900/30 rounded-lg p-4 border border-purple-500/30">
                <p className="text-sm text-purple-300 mb-2">You will pay approximately:</p>
                <div className="flex items-baseline space-x-2">
                  <p className="text-3xl font-bold text-white">
                    {currency === 'usdc' && `${parseFloat(amount).toFixed(6)} USDC`}
                    {currency === 'zec' && `${(parseFloat(amount) / rates.rates.ZEC).toFixed(8)} ZEC`}
                    {currency === 'xmr' && `${(parseFloat(amount) / rates.rates.XMR).toFixed(12)} XMR`}
                  </p>
                  {getBalanceForCurrency() && (
                    <p className="text-sm text-purple-300">
                      (Wallet: {getBalanceForCurrency()})
                    </p>
                  )}
                </div>
                {rates && currency !== 'usdc' && (
                  <p className="text-xs text-gray-400 mt-2">
                    Rate: 1 {currency.toUpperCase()} = ${currency === 'zec' ? rates.rates.ZEC : rates.rates.XMR} USD
                  </p>
                )}
              </div>
            )}

            {error && (
              <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-start space-x-3">
                <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                <p className="text-red-300 text-sm">{error}</p>
              </div>
            )}

            <button
              onClick={generatePaymentRequest}
              disabled={!amount || parseFloat(amount) <= 0 || loading}
              className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-slate-600 disabled:to-slate-600 text-white font-semibold rounded-lg transition-all shadow-lg disabled:cursor-not-allowed flex items-center justify-center space-x-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span>Generating...</span>
                </>
              ) : (
                <>
                  <span>Generate Payment Request</span>
                  <ArrowRight className="w-5 h-5" />
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {step === 2 && paymentRequest && depositAddresses && (
        <div className="space-y-6">
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
            <h2 className="text-2xl font-bold text-white mb-6">Send Payment</h2>
            
            <div className="space-y-4">
              <div className="bg-purple-900/30 rounded-lg p-4 border border-purple-500/30">
                <p className="text-sm text-purple-300 mb-1">Send exactly this amount:</p>
                <p className="text-3xl font-bold text-white mb-2">{getPaymentAmount()} {currency.toUpperCase()}</p>
                <p className="text-xs text-purple-300">≈ ${amount} USD</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Deposit Address
                  {currency === 'usdc' && network === 'starknet' && ' (Account)'}
                </label>
                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={getDepositAddress()}
                    readOnly
                    className="flex-1 px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm font-mono"
                  />
                  <button
                    onClick={() => copyToClipboard(getDepositAddress())}
                    className="p-3 bg-purple-600 hover:bg-purple-700 rounded-lg transition-colors flex-shrink-0"
                  >
                    {copied ? <CheckCircle className="w-5 h-5 text-white" /> : <Copy className="w-5 h-5 text-white" />}
                  </button>
                </div>
              </div>

              {currency === 'usdc' && (
                <div className="bg-blue-900/30 rounded-lg p-4 border border-blue-500/30">
                  <div className="flex items-start space-x-2 mb-2">
                    <AlertCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-blue-300 font-semibold">
                        Network: {network === 'starknet' ? 'StarkNet Mainnet' : network.charAt(0).toUpperCase() + network.slice(1)}
                      </p>
                      {network === 'starknet' && (
                        <p className="text-xs text-blue-200 mt-1">
                          Contract: {depositAddresses.depositAddresses.usdc.starknet.contract}
                        </p>
                      )}
                      <p className="text-xs text-blue-200 mt-1">
                        Send USDC on this network only to avoid permanent loss of funds
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {currency === 'zec' && network === 'shielded' && (
                <div className="bg-green-900/30 rounded-lg p-4 border border-green-500/30">
                  <div className="flex items-start space-x-2">
                    <Shield className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-green-300 font-semibold mb-1">
                        Shielded Transaction (Full Privacy)
                      </p>
                      <p className="text-xs text-green-200">
                        Zero-knowledge proofs ensure complete transaction privacy. Amount and sender are hidden on the blockchain.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {currency === 'xmr' && (
                <div className="bg-green-900/30 rounded-lg p-4 border border-green-500/30">
                  <div className="flex items-start space-x-2">
                    <Shield className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-green-300 font-semibold mb-1">
                        Monero Private Transaction (Mandatory)
                      </p>
                      <p className="text-xs text-green-200">
                        Ring Signatures + Stealth Addresses + RingCT. All Monero transactions are private by protocol design.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {usePrivacyRoute && (
                <div className="bg-purple-900/30 rounded-lg p-4 border border-purple-500/30">
                  <div className="flex items-start space-x-2">
                    <Shield className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-purple-300 font-semibold mb-1">
                        Privacy Routing Enabled
                      </p>
                      <p className="text-xs text-purple-200">
                        Your payment will be routed through Zcash's shielded pool with mixing delays for enhanced privacy.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {deferredAuth && (
                <div className="bg-yellow-900/30 rounded-lg p-4 border border-yellow-500/30">
                  <div className="flex items-start space-x-2">
                    <Clock className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-yellow-300 font-semibold mb-1">
                        Deferred Payment Authorization
                      </p>
                      <p className="text-xs text-yellow-200 mb-2">
                        This payment will be batched for settlement. Authorization code:
                      </p>
                      <code className="text-xs bg-slate-900/50 px-2 py-1 rounded block break-all text-yellow-100">
                        {deferredAuth.authorization}
                      </code>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
            <h3 className="text-xl font-bold text-white mb-4">Verify Transaction</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  {currency === 'xmr' ? 'Payment ID' : 'Transaction Hash / TXID'}
                </label>
                <input
                  type="text"
                  value={txHash}
                  onChange={(e) => setTxHash(e.target.value)}
                  placeholder={currency === 'xmr' ? 'Enter payment ID...' : 'Enter transaction hash (0x... or txid)'}
                  className="w-full px-4 py-3 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono text-sm"
                />
              </div>

              {error && (
                <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-start space-x-3">
                  <AlertCircle className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" />
                  <p className="text-red-300 text-sm">{error}</p>
                </div>
              )}

              {verificationResult && !verificationResult.verified && (
                <div className="bg-yellow-500/20 border border-yellow-500/50 rounded-lg p-4">
                  <div className="flex items-start space-x-2">
                    <Clock className="w-5 h-5 text-yellow-400 mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-yellow-300 text-sm font-semibold mb-1">
                        Payment Not Yet Confirmed
                      </p>
                      <p className="text-xs text-yellow-200">
                        Transaction detected but not yet confirmed. Auto-checking every 10 seconds... (Attempt {checkAttempts}/20)
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <button
                onClick={verifyPayment}
                disabled={!txHash || verifying}
                className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 disabled:from-slate-600 disabled:to-slate-600 text-white font-semibold rounded-lg transition-all shadow-lg disabled:cursor-not-allowed flex items-center justify-center space-x-2"
              >
                {verifying ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Verifying on-chain...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="w-5 h-5" />
                    <span>Verify Payment</span>
                  </>
                )}
              </button>

              {autoCheckInterval && (
                <div className="text-center">
                  <p className="text-sm text-gray-400">
                    Auto-verification enabled. Checking blockchain every 10 seconds...
                  </p>
                </div>
              )}

              <button
                onClick={resetForm}
                className="w-full py-2 bg-slate-700 hover:bg-slate-600 text-white font-medium rounded-lg transition-colors"
              >
                Cancel & Start Over
              </button>
            </div>
          </div>
        </div>
      )}

      {step === 3 && verificationResult && (
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-white/10 shadow-xl">
          <div className="text-center mb-6">
            <div className="w-20 h-20 bg-green-500 rounded-full flex items-center justify-center mx-auto mb-4 animate-pulse">
              <CheckCircle className="w-12 h-12 text-white" />
            </div>
            <h2 className="text-3xl font-bold text-white mb-2">Payment Verified!</h2>
            <p className="text-gray-300">Your payment has been confirmed on the blockchain</p>
          </div>

          <div className="bg-green-900/30 rounded-lg p-6 border border-green-500/30 space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-green-300 font-medium">Amount Paid:</span>
              <span className="text-white font-bold text-lg">{amount} USD</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-green-300 font-medium">Currency:</span>
              <span className="text-white font-semibold">{verificationResult.currency}</span>
            </div>
            {verificationResult.details?.network && (
              <div className="flex justify-between items-center">
                <span className="text-green-300 font-medium">Network:</span>
                <span className="text-white font-semibold capitalize">{verificationResult.details.network}</span>
              </div>
            )}
            {verificationResult.depositWallet && (
              <div className="flex justify-between items-start">
                <span className="text-green-300 font-medium">Deposit Wallet:</span>
                <span className="text-white font-mono text-sm text-right">
                  {verificationResult.depositWallet.slice(0, 10)}...{verificationResult.depositWallet.slice(-10)}
                </span>
              </div>
            )}
            <div className="flex justify-between items-center">
              <span className="text-green-300 font-medium">Verification Method:</span>
              <span className="text-white font-semibold">{verificationResult.verificationMethod || 'on-chain'}</span>
            </div>
            {verificationResult.details?.type && (
              <div className="flex justify-between items-center">
                <span className="text-green-300 font-medium">Privacy Level:</span>
                <span className="text-white font-semibold capitalize">
                  {verificationResult.details.type === 'shielded' ? 'Full (Zero-Knowledge)' : 
                   verificationResult.details.privacy === 'full' ? 'Full (Ring Signatures)' : 
                   'Transparent'}
                </span>
              </div>
            )}
            <div className="flex justify-between items-center">
              <span className="text-green-300 font-medium">Client ID:</span>
              <span className="text-white font-mono text-sm">{clientId.slice(0, 20)}...</span>
            </div>
          </div>

          {privacyRouteId && (
            <div className="mt-4 bg-purple-900/30 rounded-lg p-6 border border-purple-500/30">
              <div className="flex items-start space-x-3 mb-3">
                <Shield className="w-6 h-6 text-purple-400 flex-shrink-0" />
                <div>
                  <h3 className="text-white font-semibold mb-1">Privacy Routing Initiated</h3>
                  <p className="text-sm text-purple-200">
                    Your payment is being routed through Zcash's shielded pool for enhanced privacy
                  </p>
                </div>
              </div>
              <div className="bg-slate-900/50 rounded p-3">
                <div className="text-xs text-purple-300 mb-1">Privacy Route ID:</div>
                <code className="text-white font-mono text-sm">{privacyRouteId}</code>
              </div>
              <p className="text-xs text-purple-300 mt-3">
                Track your privacy route status in the Privacy Router section or Admin Dashboard
              </p>
            </div>
          )}

          {getExplorerUrl() && (
            <a
              href={getExplorerUrl()}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-4 flex items-center justify-center space-x-2 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
            >
              <span>View Transaction on Explorer</span>
              <ExternalLink className="w-4 h-4" />
            </a>
          )}

          <button
            onClick={resetForm}
            className="mt-3 w-full py-3 bg-purple-600 hover:bg-purple-700 text-white font-semibold rounded-lg transition-colors"
          >
            Make Another Payment
          </button>
        </div>
      )}
    </div>
  );
}

function StepIndicator({ number, label, active, completed }) {
  return (
    <div className="flex flex-col items-center">
      <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm transition-all ${
        completed ? 'bg-purple-600 text-white scale-110' : active ? 'bg-purple-600 text-white' : 'bg-slate-700 text-gray-400'
      }`}>
        {completed ? <CheckCircle className="w-6 h-6" /> : number}
      </div>
      <span className={`text-xs mt-2 font-medium ${active ? 'text-white' : 'text-gray-400'}`}>{label}</span>
    </div>
  );
}

function CurrencyButton({ currency, label, selected, onClick, disabled }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`py-3 px-4 rounded-lg font-medium transition-all ${
        selected
          ? 'bg-purple-600 text-white shadow-lg shadow-purple-500/50'
          : disabled
          ? 'bg-slate-700/30 text-gray-500 cursor-not-allowed'
          : 'bg-slate-700/50 text-gray-300 hover:bg-slate-700'
      }`}
    >
      {label}
    </button>
  );
}

function NetworkButton({ label, selected, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`py-2 px-4 rounded-lg text-sm font-medium transition-all ${
        selected
          ? 'bg-purple-600 text-white shadow-lg'
          : 'bg-slate-700/50 text-gray-300 hover:bg-slate-700'
      }`}
    >
      {label}
    </button>
  );
}