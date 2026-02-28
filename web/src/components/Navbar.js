import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Menu, X } from 'lucide-react';

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false);
  
  return (
    <nav className="fixed w-full z-50 glass border-b border-indigo-500/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-20">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center h-10 w-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 shadow-lg shadow-indigo-500/40">
              <Shield className="h-6 w-6 text-white" />
              <div className="absolute inset-0 bg-white/20 blur-md rounded-xl animate-pulse"></div>
            </div>
            <span className="font-bold text-2xl tracking-tight text-white">Net<span className="text-indigo-400">Sentinel</span></span>
          </div>
          
          {/* Desktop Menu */}
          <div className="hidden md:flex items-center space-x-8">
            <Link to="/" className="text-slate-300 hover:text-white transition-colors">Features</Link>
            <Link to="/pricing" className="text-slate-300 hover:text-white transition-colors">Pricing</Link>
            <Link to="/dashboard" className="text-slate-300 hover:text-white transition-colors">Dashboard</Link>
            <button className="px-6 py-2.5 rounded-full bg-indigo-500 hover:bg-indigo-600 text-white font-medium transition-all shadow-lg shadow-indigo-500/30 hover:shadow-indigo-500/50">
              Get Started
            </button>
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button onClick={() => setIsOpen(!isOpen)} className="text-slate-300 hover:text-white">
              {isOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu */}
      {isOpen && (
        <div className="md:hidden glass border-t border-slate-800">
          <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
            <Link to="/" onClick={() => setIsOpen(false)} className="block px-3 py-2 text-slate-300 hover:text-white">Features</Link>
            <Link to="/pricing" onClick={() => setIsOpen(false)} className="block px-3 py-2 text-slate-300 hover:text-white">Pricing</Link>
            <Link to="/dashboard" onClick={() => setIsOpen(false)} className="block px-3 py-2 text-slate-300 hover:text-white">Dashboard</Link>
          </div>
        </div>
      )}
    </nav>
  );
};

export default Navbar;
