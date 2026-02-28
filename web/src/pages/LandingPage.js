import React from 'react';
import { Link } from 'react-router-dom';
import { Zap, ChevronRight, Activity, Lock, Database } from 'lucide-react';
import Navbar from '../components/Navbar';

const LandingPage = () => {
  return (
    <div className="min-h-screen bg-slate-950 bg-grid relative overflow-hidden">
      {/* Background glowing orbs */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-indigo-600/30 rounded-full blur-[120px] mix-blend-screen pointer-events-none animate-pulse-glow"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-600/20 rounded-full blur-[120px] mix-blend-screen pointer-events-none animate-pulse-glow" style={{animationDelay: '2s'}}></div>

      <Navbar />

      <main className="pt-32 pb-16 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto relative z-10">
        
        {/* Hero Section */}
        <div className="text-center max-w-4xl mx-auto mt-16 mb-24 animate-float">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass border-indigo-500/30 text-indigo-300 text-sm font-medium mb-8">
            <Zap className="h-4 w-4" /> v1.0.0 Public Beta is Live
          </div>
          <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-8">
            Next-Gen <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-500">Zero Trust</span> Endpoint Security
          </h1>
          <p className="text-xl text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
            Protect your fleet with military-grade behavioral analysis, intelligent firewall manipulation, and real-time process monitoring. Prevent zero-days before they execute.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a href="/NetSentinel_Beta_v1.0.0.zip" download className="px-8 py-4 rounded-full bg-gradient-to-r from-indigo-500 to-purple-600 text-white font-bold text-lg hover:from-indigo-400 hover:to-purple-500 transition-all shadow-lg shadow-indigo-500/40 hover:shadow-indigo-500/60 flex items-center justify-center gap-2">
              Download Beta (Windows) <ChevronRight className="h-5 w-5" />
            </a>
            <Link to="/docs" className="px-8 py-4 rounded-full glass text-slate-200 font-bold text-lg hover:bg-slate-800/80 transition-all border border-slate-700 flex items-center justify-center gap-2">
              View Documentation
            </Link>
          </div>
        </div>

        {/* Feature Grid */}
        <div className="grid md:grid-cols-3 gap-6 mb-24">
          <div className="glass-card group relative overflow-hidden">
            <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/10 rounded-bl-full transition-transform group-hover:scale-110"></div>
            <Activity className="h-10 w-10 text-indigo-400 mb-6" />
            <h3 className="text-xl font-bold text-white mb-3">Behavioral Engine</h3>
            <p className="text-slate-400 leading-relaxed">
              Detects LOLBaS (Living off the Land) attacks by analyzing process lifecycles and parent-child execution chains up to Layer 4.
            </p>
          </div>

          <div className="glass-card group relative overflow-hidden">
             <div className="absolute top-0 right-0 w-32 h-32 bg-purple-500/10 rounded-bl-full transition-transform group-hover:scale-110"></div>
            <Lock className="h-10 w-10 text-purple-400 mb-6" />
            <h3 className="text-xl font-bold text-white mb-3">Active Mitigation</h3>
            <p className="text-slate-400 leading-relaxed">
              Instantly severs unauthorized connections via native Windows Firewall integration and mitigates malicious code injections.
            </p>
          </div>

          <div className="glass-card group relative overflow-hidden">
            <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 rounded-bl-full transition-transform group-hover:scale-110"></div>
            <Database className="h-10 w-10 text-blue-400 mb-6" />
            <h3 className="text-xl font-bold text-white mb-3">Cloud Config</h3>
            <p className="text-slate-400 leading-relaxed">
              Agents stay updated hourly by pulling dynamic JSON threat intelligence from our centralized SaaS infrastructure.
            </p>
          </div>
        </div>

        {/* Console Preview */}
        <div className="max-w-4xl mx-auto rounded-xl overflow-hidden glass border-slate-700/50 shadow-2xl">
          <div className="bg-slate-900/80 px-4 py-3 border-b border-slate-800 flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
            <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
            <span className="ml-2 text-xs font-mono text-slate-500">NetSentinel_Log.exe</span>
          </div>
          <div className="p-6 font-mono text-sm space-y-2 text-slate-300">
            <p className="text-indigo-400">[INFO] NetSentinel EDR Engine v1.0.0 initializing...</p>
            <p><span className="text-green-400">[OK]</span> Connecting to Cloud API for latest threat JSON...</p>
            <p><span className="text-green-400">[OK]</span> Hardware ID Authenticated. Active Subscription verified.</p>
            <p><span className="text-green-400">[OK]</span> WMI Process Monitor Started (EventSink Hooked).</p>
            <p className="text-slate-500 mt-4">--- 2 hours later ---</p>
            <p className="text-yellow-400">[WARN] Suspicious process spawned: powershell.exe (-enc JABzAE...)</p>
            <p className="text-red-400 font-bold">[ALERT] C2 Beacon Detected to IP 194.55.23.11 (RU)</p>
            <p className="text-blue-400">[ACTION] Firewall Block Rule created for 194.55.23.11</p>
            <p className="text-blue-400">[ACTION] Threat Quarantined. Parent Process suspended.</p>
          </div>
        </div>

      </main>
    </div>
  );
};

export default LandingPage;
