import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Menu, X, LogOut, User } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Navbar = () => {
    const { user, logout } = useAuth();
    const navigate = useNavigate();
    const [isOpen, setIsOpen] = useState(false);

    const handleLogout = async () => {
        await logout();
        navigate('/');
    };

    return (
        <nav className="fixed w-full z-50 glass border-b border-indigo-500/20">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex items-center justify-between h-20">
                    <Link to="/" className="flex items-center gap-3">
                        <div className="relative flex items-center justify-center h-10 w-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 shadow-lg shadow-indigo-500/40">
                            <Shield className="h-6 w-6 text-white" />
                        </div>
                        <span className="font-bold text-2xl tracking-tight text-white">Net<span className="text-indigo-400">Sentinel</span></span>
                    </Link>

                    {/* Desktop Menu */}
                    <div className="hidden md:flex items-center space-x-6">
                        <Link to="/"        className="text-slate-300 hover:text-white transition-colors">Features</Link>
                        <Link to="/docs"    className="text-slate-300 hover:text-white transition-colors">Docs</Link>
                        <Link to="/pricing" className="text-slate-300 hover:text-white transition-colors">Pricing</Link>

                        {user ? (
                            // ── Logged in ──
                            <div className="flex items-center gap-4">
                                <Link to="/dashboard" className="flex items-center gap-2 text-slate-300 hover:text-white transition-colors">
                                    <User className="h-4 w-4" /> {user.email}
                                </Link>
                                <button
                                    onClick={handleLogout}
                                    className="flex items-center gap-2 px-4 py-2 rounded-full border border-slate-700 text-slate-400 hover:text-white hover:border-slate-500 transition-all text-sm"
                                >
                                    <LogOut className="h-4 w-4" /> Logout
                                </button>
                            </div>
                        ) : (
                            // ── Logged out ──
                            <div className="flex items-center gap-3">
                                <Link to="/login" className="text-slate-300 hover:text-white transition-colors">Login</Link>
                                <Link to="/register" className="px-6 py-2.5 rounded-full bg-indigo-500 hover:bg-indigo-600 text-white font-medium transition-all shadow-lg shadow-indigo-500/30">
                                    Get Started
                                </Link>
                            </div>
                        )}
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
                <div className="md:hidden glass border-t border-slate-800 px-4 py-3 space-y-2">
                    <Link to="/"        onClick={() => setIsOpen(false)} className="block px-3 py-2 text-slate-300 hover:text-white">Features</Link>
                    <Link to="/docs"    onClick={() => setIsOpen(false)} className="block px-3 py-2 text-slate-300 hover:text-white">Docs</Link>
                    <Link to="/pricing" onClick={() => setIsOpen(false)} className="block px-3 py-2 text-slate-300 hover:text-white">Pricing</Link>
                    {user ? (
                        <>
                            <Link to="/dashboard" onClick={() => setIsOpen(false)} className="block px-3 py-2 text-indigo-400">Dashboard</Link>
                            <button onClick={() => { handleLogout(); setIsOpen(false); }} className="block px-3 py-2 text-slate-400 w-full text-left">Logout</button>
                        </>
                    ) : (
                        <>
                            <Link to="/login"    onClick={() => setIsOpen(false)} className="block px-3 py-2 text-slate-300 hover:text-white">Login</Link>
                            <Link to="/register" onClick={() => setIsOpen(false)} className="block px-3 py-2 text-indigo-400 font-medium">Get Started Free</Link>
                        </>
                    )}
                </div>
            )}
        </nav>
    );
};

export default Navbar;
