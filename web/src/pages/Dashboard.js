import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Activity, Server, AlertTriangle, Clock, LogOut, RefreshCw } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const API = 'http://localhost:5000/api';

const MonitorIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
        className="text-slate-500">
        <rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/>
        <line x1="12" x2="12" y1="17" y2="21"/>
    </svg>
);

const StatusBadge = ({ status }) => {
    const isOnline = status === 'online';
    return (
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
            isOnline ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-slate-800 text-slate-400 border-slate-700'
        }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${isOnline ? 'bg-green-400 animate-pulse' : 'bg-slate-500'}`}></span>
            {isOnline ? 'Online' : 'Offline'}
        </span>
    );
};

const SubBadge = ({ sub }) => {
    if (!sub) return null;
    const colors = {
        beta:    'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
        active:  'bg-green-500/10 text-green-400 border-green-500/20',
        expired: 'bg-red-500/10 text-red-400 border-red-500/20',
    };
    return (
        <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-semibold border ${colors[sub.status] || colors.expired}`}>
            {sub.label}
        </span>
    );
};

const Dashboard = () => {
    const { user, logout } = useAuth();
    const [endpoints,    setEndpoints]    = useState([]);
    const [alerts,       setAlerts]       = useState([]);
    const [activeTab,    setActiveTab]    = useState('endpoints');
    const [loading,      setLoading]      = useState(true);
    const [error,        setError]        = useState('');
    const [profileData,  setProfileData]  = useState(null);

    const token = localStorage.getItem('ns_token');

    const fetchData = useCallback(async () => {
        setLoading(true);
        setError('');
        try {
            const headers = { Authorization: `Bearer ${token}` };
            const [epRes, alRes, meRes] = await Promise.all([
                fetch(`${API}/agent/endpoints`, { headers }),
                fetch(`${API}/agent/alerts`,    { headers }),
                fetch(`${API}/auth/me`,         { headers }),
            ]);
            if (epRes.ok) setEndpoints(await epRes.json());
            if (alRes.ok) setAlerts(await alRes.json());
            if (meRes.ok) setProfileData(await meRes.json());
        } catch {
            setError('Could not reach the backend. Make sure the server is running.');
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => { fetchData(); }, [fetchData]);

    const sidebarItems = [
        { id: 'endpoints', icon: Server,   label: 'Endpoints' },
        { id: 'alerts',    icon: Activity, label: 'Alerts'    },
        { id: 'account',   icon: Shield,   label: 'Account'   },
    ];

    return (
        <div className="min-h-screen bg-slate-950 flex">
            {/* Sidebar */}
            <div className="w-64 glass border-r hidden md:flex flex-col pt-6">
                <div className="px-6 mb-10 flex items-center gap-2">
                    <Shield className="h-6 w-6 text-indigo-400" />
                    <span className="font-bold text-xl text-white">NetSentinel</span>
                </div>
                <div className="px-4 space-y-1 flex-1">
                    {sidebarItems.map(({ id, icon: Icon, label }) => (
                        <button key={id} onClick={() => setActiveTab(id)}
                            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left transition-colors ${
                                activeTab === id
                                    ? 'bg-indigo-500/10 text-indigo-400 font-medium border border-indigo-500/20'
                                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                            }`}>
                            <Icon className="h-5 w-5" /> {label}
                        </button>
                    ))}
                </div>
                <div className="px-4 pb-6">
                    <button onClick={logout}
                        className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors text-sm">
                        <LogOut className="h-4 w-4" /> Sign Out
                    </button>
                </div>
            </div>

            {/* Main content */}
            <div className="flex-1 p-8 overflow-auto">
                {/* Header */}
                <div className="flex justify-between items-center mb-8">
                    <div>
                        <h1 className="text-3xl font-bold text-white mb-1">
                            {activeTab === 'endpoints' && 'Your Devices'}
                            {activeTab === 'alerts'    && 'Threat Alerts'}
                            {activeTab === 'account'   && 'My Account'}
                        </h1>
                        <p className="text-slate-400 text-sm">Logged in as <span className="text-indigo-400">{user?.email}</span></p>
                    </div>
                    <div className="flex items-center gap-3">
                        <button onClick={fetchData}
                            className="flex items-center gap-2 px-4 py-2 rounded-lg glass text-slate-400 hover:text-white transition-colors text-sm border border-slate-800">
                            <RefreshCw className="h-4 w-4" /> Refresh
                        </button>
                        <Link to="/" className="text-slate-500 hover:text-slate-300 text-sm">← Back to Site</Link>
                    </div>
                </div>

                {/* Error */}
                {error && (
                    <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl p-4 mb-6 text-sm">
                        <AlertTriangle className="h-4 w-4 flex-shrink-0" /> {error}
                    </div>
                )}

                {loading ? (
                    <div className="flex items-center justify-center h-64">
                        <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
                    </div>
                ) : (
                    <>
                        {/* ── Endpoints Tab ── */}
                        {activeTab === 'endpoints' && (
                            <div className="glass rounded-xl overflow-hidden">
                                {endpoints.length === 0 ? (
                                    <div className="text-center py-20 text-slate-500">
                                        <Server className="h-12 w-12 mx-auto mb-3 opacity-30" />
                                        <p className="font-medium">No devices registered yet</p>
                                        <p className="text-sm mt-1">Download and log in to the NetSentinel app to register a device.</p>
                                    </div>
                                ) : (
                                    <table className="w-full text-left text-sm text-slate-300">
                                        <thead className="bg-slate-900 border-b border-slate-800 text-xs uppercase font-semibold text-slate-400">
                                            <tr>
                                                <th className="px-6 py-4">Hostname</th>
                                                <th className="px-6 py-4">HWID</th>
                                                <th className="px-6 py-4">OS</th>
                                                <th className="px-6 py-4">Status</th>
                                                <th className="px-6 py-4">Last Seen</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {endpoints.map(ep => (
                                                <tr key={ep.id} className="border-b border-slate-800 hover:bg-slate-800/30 transition-colors">
                                                    <td className="px-6 py-4 font-medium text-white flex items-center gap-3">
                                                        <MonitorIcon /> {ep.hostname || 'Unknown'}
                                                    </td>
                                                    <td className="px-6 py-4 font-mono text-xs text-slate-400">{ep.hwid?.substring(0, 16)}…</td>
                                                    <td className="px-6 py-4 text-slate-400 text-xs">{ep.os_version || '—'}</td>
                                                    <td className="px-6 py-4"><StatusBadge status={ep.status} /></td>
                                                    <td className="px-6 py-4 text-slate-500 text-xs flex items-center gap-1">
                                                        <Clock className="h-3 w-3" />
                                                        {new Date(ep.last_seen).toLocaleString()}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                )}
                            </div>
                        )}

                        {/* ── Alerts Tab ── */}
                        {activeTab === 'alerts' && (
                            <div className="glass rounded-xl overflow-hidden">
                                {alerts.length === 0 ? (
                                    <div className="text-center py-20 text-slate-500">
                                        <Activity className="h-12 w-12 mx-auto mb-3 opacity-30" />
                                        <p className="font-medium">No alerts recorded yet</p>
                                        <p className="text-sm mt-1">Alerts appear here as the EDR engine detects threats.</p>
                                    </div>
                                ) : (
                                    <table className="w-full text-left text-sm text-slate-300">
                                        <thead className="bg-slate-900 border-b border-slate-800 text-xs uppercase font-semibold text-slate-400">
                                            <tr>
                                                <th className="px-6 py-4">Time</th>
                                                <th className="px-6 py-4">Severity</th>
                                                <th className="px-6 py-4">Type</th>
                                                <th className="px-6 py-4">Message</th>
                                                <th className="px-6 py-4">Remote IP</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {alerts.map(a => (
                                                <tr key={a.id} className="border-b border-slate-800 hover:bg-slate-800/30 transition-colors">
                                                    <td className="px-6 py-4 text-slate-500 text-xs whitespace-nowrap">{new Date(a.created_at).toLocaleString()}</td>
                                                    <td className="px-6 py-4">
                                                        <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                                                            a.severity === 'HIGH' ? 'bg-red-500/20 text-red-400' :
                                                            a.severity === 'MED'  ? 'bg-yellow-500/20 text-yellow-400' :
                                                            'bg-slate-700 text-slate-400'
                                                        }`}>{a.severity || 'INFO'}</span>
                                                    </td>
                                                    <td className="px-6 py-4 text-slate-400 text-xs">{a.type || '—'}</td>
                                                    <td className="px-6 py-4 text-slate-300 max-w-xs truncate">{a.message}</td>
                                                    <td className="px-6 py-4 font-mono text-xs text-slate-500">{a.remote_ip || '—'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                )}
                            </div>
                        )}

                        {/* ── Account Tab ── */}
                        {activeTab === 'account' && profileData && (
                            <div className="grid md:grid-cols-2 gap-6 max-w-3xl">
                                <div className="glass-card">
                                    <h3 className="font-bold text-white mb-4 text-lg">Profile</h3>
                                    <div className="space-y-3 text-sm">
                                        <div className="flex justify-between"><span className="text-slate-400">Email</span><span className="text-white">{profileData.email}</span></div>
                                        <div className="flex justify-between"><span className="text-slate-400">Role</span><span className="text-indigo-400 capitalize">{profileData.role}</span></div>
                                        <div className="flex justify-between"><span className="text-slate-400">Member since</span><span className="text-white">{new Date(profileData.created_at).toLocaleDateString()}</span></div>
                                        <div className="flex justify-between"><span className="text-slate-400">Last login</span><span className="text-white">{profileData.last_login ? new Date(profileData.last_login).toLocaleString() : '—'}</span></div>
                                    </div>
                                </div>
                                <div className="glass-card">
                                    <h3 className="font-bold text-white mb-4 text-lg">Subscription</h3>
                                    <div className="mb-4"><SubBadge sub={profileData.subscription} /></div>
                                    <p className="text-slate-400 text-sm">{profileData.subscription?.message || 'Active subscription.'}</p>
                                    {profileData.subscription?.status === 'expired' && (
                                        <Link to="/pricing" className="mt-4 inline-block px-4 py-2 rounded-lg bg-indigo-500 text-white text-sm font-medium hover:bg-indigo-600 transition-colors">
                                            View Pricing →
                                        </Link>
                                    )}
                                </div>
                            </div>
                        )}
                    </>
                )}
            </div>
        </div>
    );
};

export default Dashboard;
