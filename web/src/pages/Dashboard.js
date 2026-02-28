import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Activity, Terminal, Server } from 'lucide-react';

const MonitorMock = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-slate-500"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>
);

const Dashboard = () => {
  return (
    <div className="min-h-screen bg-slate-950 flex">
      {/* Sidebar Mockup */}
      <div className="w-64 glass border-r hidden md:block pt-6">
        <div className="px-6 mb-10 flex items-center gap-2">
          <Shield className="h-6 w-6 text-indigo-400" />
          <span className="font-bold text-xl text-white">NetSentinel</span>
        </div>
        <div className="px-4 space-y-2">
          <a href="#" className="flex items-center gap-3 px-4 py-3 rounded-lg bg-indigo-500/10 text-indigo-400 font-medium border border-indigo-500/20">
            <Server className="h-5 w-5" /> Endpoints
          </a>
          <a href="#" className="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-white transition-colors">
            <Activity className="h-5 w-5" /> Alerts
          </a>
          <a href="#" className="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-400 hover:bg-slate-800 hover:text-white transition-colors">
            <Terminal className="h-5 w-5" /> Threat Intel
          </a>
        </div>
      </div>

      <div className="flex-1 p-8">
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-white mb-1">Your Endpoints</h1>
            <p className="text-slate-400">Manage device security policies and view real-time status.</p>
          </div>
          <Link to="/" className="text-indigo-400 hover:text-indigo-300 text-sm">← Back to Site</Link>
        </div>

        <div className="glass rounded-xl overflow-hidden">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-900 border-b border-slate-800 text-xs uppercase font-semibold text-slate-400">
              <tr>
                <th className="px-6 py-4">Device Name</th>
                <th className="px-6 py-4">HWID</th>
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4">Policy</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-slate-800 hover:bg-slate-800/30 transition-colors">
                <td className="px-6 py-4 font-medium text-white flex items-center gap-3">
                  <MonitorMock /> DESKTOP-X9F2A1
                </td>
                <td className="px-6 py-4 font-mono text-xs">A4B1-99XZ-0001</td>
                <td className="px-6 py-4">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-green-500/10 text-green-400 border border-green-500/20">
                    <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse"></span> Online
                  </span>
                </td>
                <td className="px-6 py-4 text-indigo-400">Strict (Beta)</td>
                <td className="px-6 py-4 text-right">
                  <button className="text-slate-400 hover:text-white">View</button>
                </td>
              </tr>
              <tr className="hover:bg-slate-800/30 transition-colors">
                <td className="px-6 py-4 font-medium text-white flex items-center gap-3">
                  <MonitorMock /> LAPTOP-M1-DEV
                </td>
                <td className="px-6 py-4 font-mono text-xs">C8R4-11QW-7742</td>
                <td className="px-6 py-4">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
                    <span className="h-1.5 w-1.5 rounded-full bg-slate-500"></span> Offline (2d ago)
                  </span>
                </td>
                <td className="px-6 py-4 text-indigo-400">Strict (Beta)</td>
                <td className="px-6 py-4 text-right">
                  <button className="text-slate-400 hover:text-white">View</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
