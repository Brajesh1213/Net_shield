import React from 'react';
import { CheckCircle2 } from 'lucide-react';
import Navbar from '../components/Navbar';

const PricingPage = () => {
  return (
    <div className="min-h-screen bg-slate-950 pt-32 pb-16 px-4">
      <Navbar />
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4">Enterprise Security for Everyone</h1>
          <p className="text-xl text-slate-400">Start with our Free Beta today. Upgrade when you need active mitigation.</p>
        </div>

        <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
          {/* Free Tier */}
          <div className="glass-card flex flex-col">
            <h3 className="text-2xl font-bold text-white mb-2">Community Beta</h3>
            <div className="text-4xl font-extrabold text-white mb-6">$0<span className="text-lg text-slate-400 font-normal">/mo</span></div>
            <p className="text-slate-400 mb-8 border-b border-slate-800 pb-8">Perfect for testing the waters and personal use. Passive monitoring only.</p>
            <ul className="space-y-4 mb-8 flex-1">
              <li className="flex items-center gap-3 text-slate-300"><CheckCircle2 className="h-5 w-5 text-indigo-400" /> Basic Process Telemetry</li>
              <li className="flex items-center gap-3 text-slate-300"><CheckCircle2 className="h-5 w-5 text-indigo-400" /> WMI Scanning</li>
              <li className="flex items-center gap-3 text-slate-300"><CheckCircle2 className="h-5 w-5 text-indigo-400" /> Desktop Notifications</li>
            </ul>
            <button className="w-full py-3 rounded-xl bg-slate-800 text-white font-medium hover:bg-slate-700 transition-colors">
              Current Plan
            </button>
          </div>

          {/* Premium Tier */}
          <div className="glass-card relative border-indigo-500/50 shadow-indigo-500/20 flex flex-col">
            <div className="absolute top-0 right-0 bg-indigo-500 text-white text-xs font-bold px-3 py-1 rounded-bl-lg rounded-tr-lg">
              COMING SOON
            </div>
            <h3 className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-400 mb-2">Enterprise SaaS</h3>
            <div className="text-4xl font-extrabold text-white mb-6">$10<span className="text-lg text-slate-400 font-normal">/device/mo</span></div>
            <p className="text-slate-400 mb-8 border-b border-slate-800 pb-8">Full active-defense mitigation, cloud JSON threat intel, and fleet dashboard.</p>
            <ul className="space-y-4 mb-8 flex-1">
              <li className="flex items-center gap-3 text-slate-300"><CheckCircle2 className="h-5 w-5 text-purple-400" /> Passive + Active Mitigation</li>
              <li className="flex items-center gap-3 text-slate-300"><CheckCircle2 className="h-5 w-5 text-purple-400" /> Dynamic Cloud JSON Configs</li>
              <li className="flex items-center gap-3 text-slate-300"><CheckCircle2 className="h-5 w-5 text-purple-400" /> EDR API Hooks</li>
              <li className="flex items-center gap-3 text-slate-300"><CheckCircle2 className="h-5 w-5 text-purple-400" /> Centralized Fleet Dashboard</li>
            </ul>
            <button className="w-full py-3 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 text-white font-bold shadow-lg shadow-indigo-500/25 hover:from-indigo-400 hover:to-purple-500 transition-all opacity-50 cursor-not-allowed">
              Join Waitlist
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PricingPage;
