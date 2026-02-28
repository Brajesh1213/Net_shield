import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import LandingPage   from './pages/LandingPage';
import PricingPage   from './pages/PricingPage';
import DocsPage      from './pages/DocsPage';
import Dashboard     from './pages/Dashboard';
import LoginPage     from './pages/LoginPage';
import RegisterPage  from './pages/RegisterPage';
import './index.css';

// Guard: redirect to /login if not authenticated
const PrivateRoute = ({ children }) => {
    const { user, loading } = useAuth();
    if (loading) return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        </div>
    );
    return user ? children : <Navigate to="/login" replace />;
};

const App = () => (
    <AuthProvider>
        <Router>
            <Routes>
                <Route path="/"          element={<LandingPage />} />
                <Route path="/pricing"   element={<PricingPage />} />
                <Route path="/docs"      element={<DocsPage />} />
                <Route path="/login"     element={<LoginPage />} />
                <Route path="/register"  element={<RegisterPage />} />
                <Route path="/dashboard" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
            </Routes>
        </Router>
    </AuthProvider>
);

export default App;
