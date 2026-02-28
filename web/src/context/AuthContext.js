import React, { createContext, useContext, useState, useEffect } from 'react';

const API = 'http://localhost:5000/api';
const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user, setUser]   = useState(null);
    const [loading, setLoading] = useState(true);

    // Restore session on page reload
    useEffect(() => {
        const token = localStorage.getItem('ns_token');
        if (token) {
            fetch(`${API}/auth/me`, { headers: { Authorization: `Bearer ${token}` } })
                .then(r => r.ok ? r.json() : null)
                .then(data => { if (data) setUser(data); })
                .finally(() => setLoading(false));
        } else {
            setLoading(false);
        }
    }, []);

    const login = async (email, password) => {
        const res  = await fetch(`${API}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Login failed');
        localStorage.setItem('ns_token', data.token);
        setUser(data.user);
        return data;
    };

    const register = async (email, password) => {
        const res  = await fetch(`${API}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Registration failed');
        return data;
    };

    const logout = async () => {
        const token = localStorage.getItem('ns_token');
        if (token) {
            await fetch(`${API}/auth/logout`, {
                method: 'POST', headers: { Authorization: `Bearer ${token}` }
            });
        }
        localStorage.removeItem('ns_token');
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, loading, login, register, logout }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
