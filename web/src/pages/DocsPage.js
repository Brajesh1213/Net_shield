import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
    Shield, BookOpen, Download, Terminal, Cpu, Network, FileWarning,
    Activity, Lock, Eye, Layers, Database, Globe, ChevronRight,
    Zap, AlertTriangle, Search, Server, Monitor, ArrowUp
} from 'lucide-react';
import Navbar from '../components/Navbar';

/* ────────────────────────────────────────────────────────
   SIDEBAR NAV ITEMS
   ──────────────────────────────────────────────────────── */
const sections = [
    { id: 'overview',       label: 'Overview',                icon: BookOpen },
    { id: 'architecture',   label: 'Architecture',            icon: Layers },
    { id: 'installation',   label: 'Installation',            icon: Download },
    { id: 'getting-started',label: 'Getting Started',         icon: Terminal },
    { id: 'risk-engine',    label: 'Zero Trust Risk Engine',  icon: Shield },
    { id: 'network-monitor',label: 'Network Monitor',         icon: Network },
    { id: 'file-monitor',   label: 'File Monitor',            icon: FileWarning },
    { id: 'process-monitor',label: 'Process Monitor',         icon: Cpu },
    { id: 'edr-hooks',      label: 'EDR Hooks & Injection',   icon: Lock },
    { id: 'firewall',       label: 'Firewall Blocker',        icon: AlertTriangle },
    { id: 'yara',           label: 'YARA Engine',             icon: Search },
    { id: 'electron-app',   label: 'Desktop App (Electron)',  icon: Monitor },
    { id: 'api-reference',  label: 'API Reference',           icon: Server },
    { id: 'web-dashboard',  label: 'Web Dashboard',           icon: Globe },
    { id: 'subscription',   label: 'Subscription & Licensing',icon: Zap },
    { id: 'faq',            label: 'FAQ',                     icon: Activity },
];

/* ────────────────────────────────────────────────────────
   ANIMATED SECTION WRAPPER
   ──────────────────────────────────────────────────────── */
const Section = ({ id, children }) => {
    const ref = useRef(null);
    const [visible, setVisible] = useState(false);

    useEffect(() => {
        const el = ref.current;
        if (!el) return;
        const obs = new IntersectionObserver(
            ([e]) => { if (e.isIntersecting) setVisible(true); },
            { threshold: 0.08 }
        );
        obs.observe(el);
        return () => obs.disconnect();
    }, []);

    return (
        <section
            id={id}
            ref={ref}
            className={`mb-16 transition-all duration-700 ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'}`}
        >
            {children}
        </section>
    );
};

/* ────────────────────────────────────────────────────────
   CODE BLOCK
   ──────────────────────────────────────────────────────── */
const Code = ({ children, title }) => (
    <div className="rounded-xl overflow-hidden border border-slate-800/60 my-4">
        {title && (
            <div className="bg-slate-900/90 px-4 py-2 border-b border-slate-800 flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500/70"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/70"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-green-500/70"></div>
                <span className="ml-2 text-xs font-mono text-slate-500">{title}</span>
            </div>
        )}
        <pre className="bg-slate-950/80 p-4 overflow-x-auto text-sm font-mono text-slate-300 leading-relaxed">
            <code>{children}</code>
        </pre>
    </div>
);

/* ────────────────────────────────────────────────────────
   INFO / WARNING CALLOUTS
   ──────────────────────────────────────────────────────── */
const Callout = ({ type = 'info', children }) => {
    const styles = {
        info:    'border-indigo-500/40 bg-indigo-500/5  text-indigo-300',
        warning: 'border-yellow-500/40 bg-yellow-500/5  text-yellow-300',
        danger:  'border-red-500/40    bg-red-500/5     text-red-300',
        success: 'border-emerald-500/40 bg-emerald-500/5 text-emerald-300',
    };
    const icons = {
        info: <Zap className="h-4 w-4 flex-shrink-0 mt-0.5" />,
        warning: <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />,
        danger: <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />,
        success: <Shield className="h-4 w-4 flex-shrink-0 mt-0.5" />,
    };
    return (
        <div className={`flex gap-3 rounded-lg border px-4 py-3 my-4 text-sm ${styles[type]}`}>
            {icons[type]}
            <div>{children}</div>
        </div>
    );
};

/* ────────────────────────────────────────────────────────
   TABLE COMPONENT
   ──────────────────────────────────────────────────────── */
const DocTable = ({ headers, rows }) => (
    <div className="overflow-x-auto my-4 rounded-xl border border-slate-800/60">
        <table className="w-full text-sm text-left">
            <thead className="bg-slate-900/70 text-slate-400 text-xs uppercase tracking-wider">
                <tr>
                    {headers.map((h,i) => <th key={i} className="px-4 py-3 font-medium">{h}</th>)}
                </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
                {rows.map((row, i) => (
                    <tr key={i} className="hover:bg-slate-800/20 transition-colors">
                        {row.map((cell, j) => (
                            <td key={j} className="px-4 py-3 text-slate-300">{cell}</td>
                        ))}
                    </tr>
                ))}
            </tbody>
        </table>
    </div>
);

/* ════════════════════════════════════════════════════════
   DOCS PAGE
   ════════════════════════════════════════════════════════ */
const DocsPage = () => {
    const [activeSection, setActiveSection] = useState('overview');
    const [showScrollTop, setShowScrollTop] = useState(false);

    /* Track scroll position for sidebar highlighting */
    useEffect(() => {
        const handler = () => {
            setShowScrollTop(window.scrollY > 500);
            const offsets = sections.map(s => {
                const el = document.getElementById(s.id);
                return { id: s.id, top: el ? el.getBoundingClientRect().top : 99999 };
            });
            const current = offsets.filter(o => o.top < 200).pop();
            if (current) setActiveSection(current.id);
        };
        window.addEventListener('scroll', handler, { passive: true });
        return () => window.removeEventListener('scroll', handler);
    }, []);

    const scrollTo = (id) => {
        document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };

    return (
        <div className="min-h-screen bg-slate-950 bg-grid relative overflow-hidden">
            {/* Glow orbs */}
            <div className="absolute top-[-15%] left-[-8%] w-[35%] h-[35%] bg-indigo-600/20 rounded-full blur-[120px] pointer-events-none"></div>
            <div className="absolute bottom-[-15%] right-[-8%] w-[35%] h-[35%] bg-purple-600/15 rounded-full blur-[120px] pointer-events-none"></div>

            <Navbar />

            <div className="pt-28 pb-16 px-4 sm:px-6 lg:px-8 max-w-[1400px] mx-auto relative z-10">
                {/* Hero */}
                <div className="text-center mb-16">
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass border-indigo-500/30 text-indigo-300 text-sm font-medium mb-6">
                        <BookOpen className="h-4 w-4" /> Documentation v1.0.0
                    </div>
                    <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight mb-4">
                        Net<span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-purple-500">Sentinel</span> Docs
                    </h1>
                    <p className="text-lg text-slate-400 max-w-2xl mx-auto">
                        Everything you need to understand, deploy, and operate NetSentinel — your Zero Trust endpoint security platform.
                    </p>
                </div>

                <div className="flex gap-8">
                    {/* ──── SIDEBAR ──── */}
                    <aside className="hidden lg:block w-64 flex-shrink-0">
                        <nav className="sticky top-28 glass rounded-2xl p-4 space-y-1 max-h-[calc(100vh-8rem)] overflow-y-auto">
                            <p className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-3 px-3">Contents</p>
                            {sections.map(s => {
                                const Icon = s.icon;
                                const isActive = activeSection === s.id;
                                return (
                                    <button
                                        key={s.id}
                                        onClick={() => scrollTo(s.id)}
                                        className={`w-full text-left flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all
                                            ${isActive
                                                ? 'bg-indigo-500/15 text-indigo-300 font-medium'
                                                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'}`}
                                    >
                                        <Icon className="h-3.5 w-3.5 flex-shrink-0" />
                                        {s.label}
                                    </button>
                                );
                            })}
                        </nav>
                    </aside>

                    {/* ──── MAIN CONTENT ──── */}
                    <main className="flex-1 min-w-0">

                        {/* ─── OVERVIEW ──────────────────────────────────── */}
                        <Section id="overview">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <BookOpen className="h-7 w-7 text-indigo-400" /> Overview
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    <strong className="text-white">NetSentinel</strong> is a next-generation Endpoint Detection & Response (EDR) platform built from the ground up for Windows. It combines a native C++17 monitoring engine with an Electron desktop application and a cloud-connected SaaS backend to deliver real-time threat detection, behavioral analysis, and active mitigation.
                                </p>
                                <p className="text-slate-300 leading-relaxed mb-6">
                                    Unlike traditional antivirus software that relies on signature matching alone, NetSentinel operates on a <strong className="text-indigo-300">Zero Trust</strong> security model — every connection, process, and file is treated as potentially hostile until proven safe through a multi-layered verification pipeline.
                                </p>
                                <h3 className="text-lg font-semibold text-white mb-3">Key Capabilities</h3>
                                <div className="grid sm:grid-cols-2 gap-3">
                                    {[
                                        ['5-Layer Zero Trust Risk Engine', 'Port → Process Integrity → Parent Chain → Behavioral → Geolocation'],
                                        ['Real-Time Network Monitor', 'TCP/UDP IPv4+IPv6 connection scanning every 2 seconds'],
                                        ['File System Monitor', 'Steganography detection, malware drops, startup persistence'],
                                        ['Process Monitor (EDR)', 'WMI real-time events, exploit chains, masquerade attacks, memory injection'],
                                        ['Active Mitigation', 'Windows Firewall integration, process termination, file quarantine'],
                                        ['YARA Scanning Engine', 'Custom rules for network payloads and process memory'],
                                        ['Cloud Threat Intelligence', 'Hourly JSON config updates from centralized SaaS API'],
                                        ['Single-Device Licensing', 'JWT + session token auth with HWID-based device binding'],
                                    ].map(([title, desc], i) => (
                                        <div key={i} className="flex gap-3 p-3 rounded-lg bg-slate-800/30 border border-slate-800/50">
                                            <ChevronRight className="h-4 w-4 text-indigo-400 mt-1 flex-shrink-0" />
                                            <div>
                                                <span className="text-white font-medium text-sm">{title}</span>
                                                <p className="text-slate-400 text-xs mt-0.5">{desc}</p>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </Section>

                        {/* ─── ARCHITECTURE ──────────────────────────────── */}
                        <Section id="architecture">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Layers className="h-7 w-7 text-purple-400" /> Architecture
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-6">
                                    NetSentinel is a <strong className="text-white">4-layer system</strong> where each layer handles a distinct responsibility:
                                </p>
                                <div className="space-y-4 mb-6">
                                    {[
                                        { num: '01', title: 'C++ Core Engine', desc: 'Low-level Windows API integration — TCP/UDP table monitoring, process inspection, WMI events, memory scanning, firewall manipulation. Compiled as a standalone .exe.', color: 'indigo' },
                                        { num: '02', title: 'Electron Desktop App', desc: 'GUI wrapper that spawns the C++ engine as a child process, parses stdout, performs GeoIP enrichment, manages auth sessions, and provides toast notifications.', color: 'purple' },
                                        { num: '03', title: 'Node.js Backend API', desc: 'REST API handling authentication (JWT + session tokens), subscription management, endpoint registration, threat intelligence delivery, and alert storage.', color: 'blue' },
                                        { num: '04', title: 'React Web Dashboard', desc: 'SaaS web interface for remote fleet monitoring, alert history, device management, and subscription billing.', color: 'emerald' },
                                    ].map((layer, i) => (
                                        <div key={i} className={`flex gap-4 p-4 rounded-xl bg-slate-800/20 border border-${layer.color}-500/20 hover:border-${layer.color}-500/40 transition-colors`}>
                                            <span className={`text-2xl font-black text-${layer.color}-500/40`}>{layer.num}</span>
                                            <div>
                                                <h4 className="text-white font-semibold">{layer.title}</h4>
                                                <p className="text-slate-400 text-sm mt-1">{layer.desc}</p>
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                <h3 className="text-lg font-semibold text-white mb-3">Communication Flow</h3>
                                <Code title="data-flow.txt">{`┌─────────────────┐    stdout/pipe     ┌─────────────────┐
│  C++ Engine     │ ─────────────────▶ │  Electron App   │
│  (NetSentinel.  │                    │  (main.js)      │
│   exe)          │                    │                 │
└─────────────────┘                    └────────┬────────┘
                                                │ HTTP REST
                                                ▼
                                       ┌─────────────────┐
                                       │  Node.js API    │
                                       │  (Express)      │◀── React Web Dashboard
                                       └────────┬────────┘
                                                │ SQLite
                                                ▼
                                       ┌─────────────────┐
                                       │  netsentinel.db │
                                       └─────────────────┘`}
                                </Code>
                            </div>
                        </Section>

                        {/* ─── INSTALLATION ──────────────────────────────── */}
                        <Section id="installation">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Download className="h-7 w-7 text-emerald-400" /> Installation
                            </h2>
                            <div className="glass-card">
                                <h3 className="text-lg font-semibold text-white mb-3">System Requirements</h3>
                                <DocTable
                                    headers={['Component', 'Requirement']}
                                    rows={[
                                        ['Operating System', 'Windows 10/11 (x64)'],
                                        ['RAM', '4 GB minimum, 8 GB recommended'],
                                        ['Disk Space', '~100 MB'],
                                        ['Runtime', '.NET Framework 4.6+ (pre-installed on Win10+)'],
                                        ['Admin Rights', 'Optional — required for Active Mitigation mode'],
                                        ['Network', 'Internet connection for cloud threat intel & GeoIP'],
                                    ]}
                                />

                                <h3 className="text-lg font-semibold text-white mb-3 mt-6">Option 1: Download Pre-Built Installer</h3>
                                <ol className="list-decimal list-inside space-y-2 text-slate-300 mb-6">
                                    <li>Download the latest <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">NetSentinel_Beta_v1.0.0.zip</code> from the home page</li>
                                    <li>Extract the ZIP file</li>
                                    <li>Run <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">NetSentinel Setup.exe</code></li>
                                    <li>Follow the NSIS installer wizard</li>
                                    <li>Launch NetSentinel from your Desktop shortcut</li>
                                </ol>

                                <h3 className="text-lg font-semibold text-white mb-3">Option 2: Build from Source</h3>
                                <Code title="terminal">{`# Prerequisites: MinGW/GCC or MSVC, CMake 3.16+, Node.js 18+

# 1. Build the C++ engine
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release

# 2. Start the backend API
cd ../backend
npm install
cp .env.example .env          # configure your secrets
npm start                     # runs on http://localhost:5000

# 3. Run the Electron desktop app
cd ../app
npm install
npm start                     # opens the GUI

# 4. (Optional) Run the web dashboard
cd ../web
npm install
npm start                     # opens on http://localhost:3000`}
                                </Code>

                                <Callout type="warning">
                                    <strong>YARA support:</strong> To enable YARA scanning, rebuild with <code className="px-1.5 py-0.5 rounded bg-slate-800 text-yellow-300 text-xs">cmake .. -DUSE_YARA=ON</code>. You must have YARA headers in <code className="text-yellow-300">include/</code> and the library in <code className="text-yellow-300">lib/</code>.
                                </Callout>
                            </div>
                        </Section>

                        {/* ─── GETTING STARTED ───────────────────────────── */}
                        <Section id="getting-started">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Terminal className="h-7 w-7 text-yellow-400" /> Getting Started
                            </h2>
                            <div className="glass-card">
                                <div className="space-y-6">
                                    {[
                                        { step: 1, title: 'Create an Account', desc: 'Register at the NetSentinel website or directly in the app. All new accounts receive 90 days of free Beta access.' },
                                        { step: 2, title: 'Login in the Desktop App', desc: 'The Electron app presents a login screen on first run. Enter your credentials — this generates a session token and binds your hardware ID (HWID) to a single device.' },
                                        { step: 3, title: 'Engine Auto-Starts', desc: 'After successful login, the C++ monitoring engine launches automatically. You\'ll see the live console output in the "Console" tab.' },
                                        { step: 4, title: 'Choose Your Protection Level', desc: 'Running without admin = Monitor Mode (detect-only). Click "Run as Admin" for Full Protection (firewall blocking + process termination).' },
                                        { step: 5, title: 'Monitor Threats', desc: 'Switch to the "Dashboard" tab for real-time threat timeline charts, or check the "Threats" tab for a detailed alert table.' },
                                    ].map(({ step, title, desc }) => (
                                        <div key={step} className="flex gap-4">
                                            <div className="flex-shrink-0 w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white font-bold shadow-lg shadow-indigo-500/30">
                                                {step}
                                            </div>
                                            <div>
                                                <h4 className="text-white font-semibold">{title}</h4>
                                                <p className="text-slate-400 text-sm mt-1">{desc}</p>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                                <Callout type="info">
                                    <strong>Single-device enforcement:</strong> Logging in on a new device automatically revokes the session on the previous device. Only one active device per account is allowed.
                                </Callout>
                            </div>
                        </Section>

                        {/* ─── ZERO TRUST RISK ENGINE ────────────────────── */}
                        <Section id="risk-engine">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Shield className="h-7 w-7 text-indigo-400" /> Zero Trust Risk Engine
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-6">
                                    The core of NetSentinel is a <strong className="text-white">5-layer risk assessment pipeline</strong> that follows the Zero Trust principle: <em className="text-indigo-300">"guilty until proven innocent."</em> Every network connection starts at MEDIUM risk and is evaluated through each layer sequentially. If any layer elevates risk to HIGH or CRITICAL, an alert fires immediately and processing stops.
                                </p>

                                <div className="space-y-3 mb-6">
                                    {[
                                        { layer: 'Layer 1: Port Policy', desc: 'Checks remote/local ports against a database of known C2 ports (Metasploit 4444, IRC 6667, crypto mining 3333, etc.) and suspicious port ranges.', risk: 'HIGH if malicious port detected' },
                                        { layer: 'Layer 2: Process Integrity', desc: 'Verifies the process executable — checks against known malware names (mimikatz, nc.exe, xmrig), detects LOLBaS abuse (PowerShell/cmd making outbound connections), and validates digital signatures.', risk: 'HIGH if known malware or LOLBaS detected' },
                                        { layer: 'Layer 3: Parent Process Chain', desc: 'Validates the process lineage — checks if SYSTEM-context processes are running outside trusted locations (System32/SysWOW64). Future: full parent chain walking.', risk: 'MEDIUM if suspicious parent context' },
                                        { layer: 'Layer 4: Behavioral Analysis', desc: 'Tracks per-PID connection patterns over time. Detects C2 beaconing (~60s interval, 10+ hits), port scanning (>50 ports), worm behavior (>10 conn/sec), data exfiltration (>10MB upload with 5:1 ratio), and crypto mining.', risk: 'HIGH if anomalous patterns detected' },
                                        { layer: 'Layer 5: Geolocation Policy', desc: 'Cross-references destination IPs with high-risk country codes (KP, IR, SY, PK, RU, CN). Requires GeoIP database or cloud lookup.', risk: 'HIGH if high-risk country connection' },
                                    ].map(({ layer, desc, risk }, i) => (
                                        <div key={i} className="p-4 rounded-xl bg-slate-800/20 border border-slate-800/50 hover:border-indigo-500/30 transition-colors">
                                            <div className="flex items-center justify-between mb-2">
                                                <h4 className="text-white font-semibold text-sm">{layer}</h4>
                                                <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20">{risk}</span>
                                            </div>
                                            <p className="text-slate-400 text-sm">{desc}</p>
                                        </div>
                                    ))}
                                </div>

                                <h3 className="text-lg font-semibold text-white mb-3">Risk Levels</h3>
                                <DocTable
                                    headers={['Level', 'Visual', 'Action']}
                                    rows={[
                                        ['CRITICAL', '🔴', 'Immediate alert + firewall block + process termination'],
                                        ['HIGH',     '🟠', 'Alert to console + attempt block + log to file'],
                                        ['MEDIUM',   '🟡', 'Silent log to file only (not shown in GUI)'],
                                        ['LOW',      '🟢', 'Trusted process — no action needed'],
                                    ]}
                                />

                                <h3 className="text-lg font-semibold text-white mb-3 mt-6">Trusted Process Whitelist</h3>
                                <p className="text-slate-400 text-sm mb-3">
                                    To prevent false positives, developer tools and known legitimate high-connection applications are automatically whitelisted from behavioral analysis:
                                </p>
                                <Code title="trusted_processes.txt">{`IDEs:       code.exe, idea64.exe, clion64.exe, pycharm64.exe, webstorm64.exe
Build:      cmake.exe, ninja.exe, msbuild.exe, gcc.exe, g++.exe, clang.exe
Runtime:    node.exe, python.exe, pip.exe, npm.exe, yarn.exe, git.exe
Browsers:   chrome.exe, firefox.exe, msedge.exe, brave.exe, opera.exe
Apps:       discord.exe, slack.exe, teams.exe, spotify.exe, steam.exe
System:     svchost.exe, system, system idle process`}
                                </Code>
                            </div>
                        </Section>

                        {/* ─── NETWORK MONITOR ───────────────────────────── */}
                        <Section id="network-monitor">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Network className="h-7 w-7 text-cyan-400" /> Network Monitor
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    NetSentinel polls the Windows IP Helper API every <strong className="text-white">2 seconds</strong> to enumerate all active TCP and UDP connections — both IPv4 and IPv6. Each connection is enriched with process info from the <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">ProcessCache</code> and deduplicated before risk assessment.
                                </p>
                                <DocTable
                                    headers={['Feature', 'Details']}
                                    rows={[
                                        ['Protocols', 'TCP (IPv4 + IPv6) and UDP (IPv4 + IPv6)'],
                                        ['API Used', 'GetExtendedTcpTable / GetExtendedUdpTable (iphlpapi.dll)'],
                                        ['Polling Rate', 'Every 2 seconds (configurable via kPollingIntervalMs)'],
                                        ['Deduplication', 'Connection key = PID:RemoteIP:RemotePort:Protocol'],
                                        ['Process Info', 'Cached via ProcessCache singleton (OpenProcess + GetModuleFileNameEx)'],
                                        ['Loopback', 'Included by default (to detect local attack simulations)'],
                                        ['Multicast', 'Filtered out automatically'],
                                    ]}
                                />
                            </div>
                        </Section>

                        {/* ─── FILE MONITOR ──────────────────────────────── */}
                        <Section id="file-monitor">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <FileWarning className="h-7 w-7 text-amber-400" /> File Monitor
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    The file monitor watches critical user directories for suspicious file activity using the Windows <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">ReadDirectoryChangesW</code> API with overlapped I/O.
                                </p>
                                <h3 className="text-lg font-semibold text-white mb-3">Watched Directories</h3>
                                <div className="grid sm:grid-cols-2 gap-2 mb-4">
                                    {['Downloads', 'Desktop', 'Temp / AppData\\Local\\Temp', 'Startup (auto-run)'].map((d, i) => (
                                        <div key={i} className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-800/30 border border-slate-800/50 text-sm text-slate-300">
                                            <Eye className="h-3.5 w-3.5 text-amber-400" /> {d}
                                        </div>
                                    ))}
                                </div>

                                <h3 className="text-lg font-semibold text-white mb-3">Detection Types</h3>
                                <DocTable
                                    headers={['Threat Type', 'Description', 'How Detected']}
                                    rows={[
                                        ['Steganography', 'Executable hidden inside an image/document file', 'MZ PE header (0x4D 0x5A) at byte 0 of .jpg/.png/.pdf files'],
                                        ['Malware Drop', 'Suspicious executable appearing in user folder', 'New .exe/.dll/.scr/.pif file creation detected'],
                                        ['Script Drop', 'Malicious script file creation', 'New .ps1/.bat/.vbs/.js/.hta file detected'],
                                        ['Startup Persistence', 'File added to Windows Startup folder', 'Any new file in CSIDL_STARTUP directory'],
                                    ]}
                                />
                                <Callout type="success">
                                    <strong>Smart filtering:</strong> Known benign files are automatically whitelisted — PowerShell policy test scripts (<code className="text-emerald-300">__PSScriptPolicyTest_*</code>), Windows Update temp files, Defender engine files, and NSIS installer temps.
                                </Callout>
                            </div>
                        </Section>

                        {/* ─── PROCESS MONITOR ───────────────────────────── */}
                        <Section id="process-monitor">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Cpu className="h-7 w-7 text-violet-400" /> Process Monitor
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    The process monitor is NetSentinel's EDR-lite engine. It uses <strong className="text-white">WMI event subscriptions</strong> (<code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">__InstanceCreationEvent</code>) for real-time process creation notifications — no polling needed.
                                </p>

                                <h3 className="text-lg font-semibold text-white mb-3">Detection Capabilities</h3>
                                <DocTable
                                    headers={['Detection', 'Description', 'Example']}
                                    rows={[
                                        ['Exploit Chain', 'Shell process spawned by a suspicious parent', 'WhatsApp → cmd.exe (image payload exploit)'],
                                        ['Suspicious Path', 'Process running from a high-risk directory', 'svchost.exe in Downloads\\ or Temp\\'],
                                        ['Masquerade Attack', 'System process name but wrong file path', 'lsass.exe outside System32 (malware impersonation)'],
                                        ['Memory Injection', 'Unbacked executable memory (RWX) without file mapping', 'Reflective DLL injection, process hollowing'],
                                        ['NOP Sled', 'Large blocks of 0x90 bytes (buffer overflow shellcode)', '40+ consecutive NOP instructions in private memory'],
                                    ]}
                                />

                                <Callout type="info">
                                    <strong>Initial snapshot:</strong> On startup, the process monitor scans all existing processes via <code className="text-indigo-300">CreateToolhelp32Snapshot</code>, then switches to event-driven WMI monitoring for new process creation.
                                </Callout>
                            </div>
                        </Section>

                        {/* ─── EDR HOOKS ──────────────────────────────────── */}
                        <Section id="edr-hooks">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Lock className="h-7 w-7 text-emerald-400" /> EDR Hooks & Injection Defense
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    NetSentinel proactively injects a protective DLL (<code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">NetSentinel_Hook.dll</code>) into new processes. This DLL hooks critical Windows APIs to block malicious behavior from within the target process itself.
                                </p>

                                <h3 className="text-lg font-semibold text-white mb-3">How It Works</h3>
                                <ol className="list-decimal list-inside space-y-2 text-slate-300 mb-4 text-sm">
                                    <li>A new process is detected via WMI event</li>
                                    <li>NetSentinel opens the target process with sufficient access rights</li>
                                    <li>Allocates memory in the target via <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">VirtualAllocEx</code></li>
                                    <li>Writes the DLL path into the allocated memory</li>
                                    <li>Creates a remote thread calling <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">LoadLibraryW</code> to load the hook DLL</li>
                                    <li>The DLL hooks <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">CreateRemoteThread</code> inside the target — preventing it from injecting into other processes</li>
                                </ol>

                                <Callout type="warning">
                                    <strong>Admin required:</strong> DLL injection requires elevated privileges. Without admin rights, this feature is silently skipped and the monitor runs in passive mode only.
                                </Callout>
                            </div>
                        </Section>

                        {/* ─── FIREWALL ───────────────────────────────────── */}
                        <Section id="firewall">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <AlertTriangle className="h-7 w-7 text-red-400" /> Firewall Blocker
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    When a HIGH or CRITICAL risk connection is detected, NetSentinel can automatically create Windows Firewall rules to block the malicious traffic. It uses <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">netsh advfirewall</code> commands executed via <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">CreateProcessW</code> (hidden window).
                                </p>
                                <DocTable
                                    headers={['Block Type', 'Command Pattern']}
                                    rows={[
                                        ['Block by IP:Port', 'netsh advfirewall firewall add rule name="NetSentinel_Block_IP_PORT" dir=out action=block remoteip=IP protocol=TCP remoteport=PORT'],
                                        ['Block by Process', 'netsh advfirewall firewall add rule name="NetSentinel_Block_Process_NAME" dir=out action=block program="PATH"'],
                                        ['Fallback: Kill Process', 'TerminateProcess() for same-user processes when firewall is unavailable'],
                                    ]}
                                />
                                <Callout type="danger">
                                    <strong>Safety net:</strong> Trusted developer processes (IDEs, browsers, build tools) are NEVER terminated, even if they trigger behavioral false positives. They are logged with a <code className="text-red-300">[SKIP KILL]</code> tag instead.
                                </Callout>
                            </div>
                        </Section>

                        {/* ─── YARA ───────────────────────────────────────── */}
                        <Section id="yara">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Search className="h-7 w-7 text-orange-400" /> YARA Engine
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    NetSentinel includes an optional YARA integration for deep content scanning of both network payloads and process memory regions. Enable it at build time with <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">-DUSE_YARA=ON</code>.
                                </p>
                                <h3 className="text-lg font-semibold text-white mb-3">Included Rule Categories</h3>
                                <DocTable
                                    headers={['Rule', 'Threat Level', 'Description']}
                                    rows={[
                                        ['Metasploit_Meterpreter_Reverse_TCP', 'Critical', 'Detects Meterpreter stager patterns and ReflectiveLoader strings'],
                                        ['CobaltStrike_Beacon', 'Critical', 'Beacon DLL strings, malleable C2 profile indicators'],
                                        ['Suspicious_Powershell_Execution', 'High', 'PowerShell with -ExecutionPolicy Bypass, -enc, -w hidden flags'],
                                        ['Malware_Download_And_Execute', 'High', 'Invoke-WebRequest, certutil -urlcache, bitsadmin patterns'],
                                        ['Cryptominer_Stratum_Protocol', 'High', 'Stratum mining.subscribe/mining.authorize JSON-RPC calls'],
                                        ['Reverse_Shell_Signatures', 'Critical', 'nc -e, bash -i, Python socket reverse shells'],
                                        ['Log4j_JNDI_Exploit', 'Critical', '${jndi:ldap://} and variants in payloads'],
                                        ['Ransomware_File_Extensions', 'Medium', '.wannacry, .lockbit, .ryuk extension mentions'],
                                    ]}
                                />
                            </div>
                        </Section>

                        {/* ─── ELECTRON APP ──────────────────────────────── */}
                        <Section id="electron-app">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Monitor className="h-7 w-7 text-sky-400" /> Desktop App (Electron)
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    The Electron app is the primary user interface. It manages authentication, spawns the C++ engine, and provides real-time visualization of threats.
                                </p>
                                <h3 className="text-lg font-semibold text-white mb-3">Features</h3>
                                <div className="grid sm:grid-cols-2 gap-2 mb-4">
                                    {[
                                        'Login overlay with session persistence',
                                        'System tray icon (minimize to tray)',
                                        'Real-time console log streaming',
                                        'Threat timeline chart (Chart.js)',
                                        'Threat breakdown doughnut chart',
                                        'Threats table with badge icons',
                                        'GeoIP enrichment via ip-api.com',
                                        'Toast notifications for HIGH/CRITICAL',
                                        'UAC elevation (Run as Admin button)',
                                        'Subscription status banner',
                                    ].map((f, i) => (
                                        <div key={i} className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-800/30 border border-slate-800/50 text-sm text-slate-300">
                                            <ChevronRight className="h-3 w-3 text-sky-400" /> {f}
                                        </div>
                                    ))}
                                </div>

                                <h3 className="text-lg font-semibold text-white mb-3">Security Model</h3>
                                <Code title="preload.js security">{`// Context Isolation: ON
// Node Integration: OFF
// IPC via contextBridge.exposeInMainWorld()
// — Renderer has ZERO access to Node.js APIs
// — All system interaction goes through IPC handlers`}
                                </Code>
                            </div>
                        </Section>

                        {/* ─── API REFERENCE ─────────────────────────────── */}
                        <Section id="api-reference">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Server className="h-7 w-7 text-teal-400" /> API Reference
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    The backend API runs on <code className="px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 text-xs">http://localhost:5000/api</code>. Authentication uses JWT tokens (for web dashboard) and session tokens (for Electron/C++ agent).
                                </p>

                                <h3 className="text-lg font-semibold text-white mb-3">Authentication Endpoints</h3>
                                <DocTable
                                    headers={['Method', 'Endpoint', 'Auth', 'Description']}
                                    rows={[
                                        ['POST', '/api/auth/register', 'None', 'Create a new account (email + password)'],
                                        ['POST', '/api/auth/login', 'None', 'Login → returns JWT + session_token'],
                                        ['GET', '/api/auth/me', 'JWT', 'Get current user profile + subscription'],
                                        ['POST', '/api/auth/logout', 'JWT', 'Invalidate session token + HWID binding'],
                                    ]}
                                />

                                <h3 className="text-lg font-semibold text-white mb-3 mt-6">Agent Endpoints</h3>
                                <DocTable
                                    headers={['Method', 'Endpoint', 'Auth', 'Description']}
                                    rows={[
                                        ['POST', '/api/agent/activate', 'Session Token', 'Bind HWID to session (runs after login)'],
                                        ['GET', '/api/agent/intelligence', 'X-Session-Token + X-HWID headers', 'Fetch threat intel JSON config'],
                                        ['GET', '/api/agent/subscription', 'X-Session-Token + X-HWID headers', 'Check subscription status'],
                                        ['POST', '/api/agent/alert', 'X-Session-Token + HWID in body', 'Log a threat alert from the agent'],
                                        ['GET', '/api/agent/endpoints', 'JWT', 'List registered devices (web dashboard)'],
                                        ['GET', '/api/agent/alerts', 'JWT', 'List recent alerts (web dashboard)'],
                                    ]}
                                />

                                <h3 className="text-lg font-semibold text-white mb-3 mt-6">Rate Limiting</h3>
                                <DocTable
                                    headers={['Scope', 'Window', 'Max Requests']}
                                    rows={[
                                        ['Auth endpoints (/api/auth/*)', '15 minutes', '5 requests'],
                                        ['General API (/api/*)', '15 minutes', '100 requests'],
                                    ]}
                                />

                                <h3 className="text-lg font-semibold text-white mb-3 mt-6">Example: Login Flow</h3>
                                <Code title="curl">{`# 1. Login
curl -X POST http://localhost:5000/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "user@example.com", "password": "mypassword"}'

# Response:
# {
#   "token": "eyJhbG...",          ← JWT for web dashboard
#   "session_token": "a1b2c3...",  ← for Electron/agent
#   "user": { "id": 1, "email": "...", "subscription": {...} }
# }

# 2. Activate agent
curl -X POST http://localhost:5000/api/agent/activate \\
  -H "Content-Type: application/json" \\
  -d '{"session_token":"a1b2c3...","hwid":"abc123","hostname":"MY-PC"}'

# 3. Fetch threat intel
curl http://localhost:5000/api/agent/intelligence \\
  -H "X-Session-Token: a1b2c3..." \\
  -H "X-HWID: abc123"`}
                                </Code>
                            </div>
                        </Section>

                        {/* ─── WEB DASHBOARD ──────────────────────────────── */}
                        <Section id="web-dashboard">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Globe className="h-7 w-7 text-pink-400" /> Web Dashboard
                            </h2>
                            <div className="glass-card">
                                <p className="text-slate-300 leading-relaxed mb-4">
                                    The React web dashboard provides remote monitoring capabilities. It communicates with the backend via JWT-authenticated REST APIs.
                                </p>
                                <DocTable
                                    headers={['Page', 'Route', 'Description']}
                                    rows={[
                                        ['Landing Page', '/', 'Product showcase with features, console preview, and download CTA'],
                                        ['Documentation', '/docs', 'This comprehensive documentation page'],
                                        ['Pricing', '/pricing', 'Community Beta (free) and Enterprise SaaS plans'],
                                        ['Login', '/login', 'Email + password authentication'],
                                        ['Register', '/register', 'Create a new account (90-day free Beta)'],
                                        ['Dashboard', '/dashboard', 'Protected route — device list, alert history, real-time stats'],
                                    ]}
                                />
                                <p className="text-slate-400 text-sm mt-4">
                                    <strong className="text-slate-300">Tech Stack:</strong> React 19, React Router 7, Tailwind CSS 3, Lucide Icons
                                </p>
                            </div>
                        </Section>

                        {/* ─── SUBSCRIPTION ───────────────────────────────── */}
                        <Section id="subscription">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Zap className="h-7 w-7 text-yellow-400" /> Subscription & Licensing
                            </h2>
                            <div className="glass-card">
                                <DocTable
                                    headers={['Plan', 'Price', 'Duration', 'Features']}
                                    rows={[
                                        ['Community Beta', 'Free', '90 days from registration', 'Full monitoring, passive detection, desktop notifications'],
                                        ['Enterprise SaaS', '$10/device/mo', 'Ongoing', 'Active mitigation, cloud threat intel, fleet dashboard, priority support'],
                                    ]}
                                />

                                <h3 className="text-lg font-semibold text-white mb-3 mt-6">Subscription States</h3>
                                <DocTable
                                    headers={['Status', 'Label', 'Behavior']}
                                    rows={[
                                        ['beta', 'Beta', 'Full access — countdown shown when <7 days remaining'],
                                        ['active', 'Active', 'Paid subscription — full features until expiration date'],
                                        ['expired', 'Expired', 'App shows banner with renewal CTA — monitoring continues in read-only'],
                                    ]}
                                />

                                <h3 className="text-lg font-semibold text-white mb-3 mt-6">Device Enforcement</h3>
                                <p className="text-slate-300 text-sm">
                                    Each account is bound to a single device via Hardware ID (HWID). The HWID is a SHA-256 hash of the machine's hostname, platform, architecture, and CPU model. Logging in on a new device automatically revokes the previous session. The Electron app polls subscription status every 30 minutes.
                                </p>
                            </div>
                        </Section>

                        {/* ─── FAQ ────────────────────────────────────────── */}
                        <Section id="faq">
                            <h2 className="text-3xl font-bold text-white mb-4 flex items-center gap-3">
                                <Activity className="h-7 w-7 text-emerald-400" /> FAQ
                            </h2>
                            <div className="space-y-3">
                                {[
                                    { q: 'Does NetSentinel replace my antivirus?', a: 'No. NetSentinel is an EDR (Endpoint Detection & Response) tool that complements your existing antivirus. It focuses on behavioral analysis, network monitoring, and zero-day detection — areas where traditional AV is weakest.' },
                                    { q: 'Will it slow down my computer?', a: 'The C++ engine uses ~15-30 MB of RAM and polls every 2 seconds. WMI event subscriptions are kernel-level callbacks with near-zero overhead. CPU usage is typically <1%.' },
                                    { q: 'Why do I need admin rights?', a: 'Admin rights are optional but recommended. Without admin: Monitor Mode (detect + alert). With admin: Full Protection (firewall blocking, process termination, DLL injection defense).' },
                                    { q: 'Can I use it on multiple computers?', a: 'Each account supports one active device. Logging in on a new device automatically logs out the previous one. Enterprise multi-device licensing is coming soon.' },
                                    { q: 'What data is sent to the cloud?', a: 'Only authentication tokens and anonymous threat alerts (IP, process name, risk level). No personal files, browsing history, or keystrokes are ever transmitted.' },
                                    { q: 'Does it work offline?', a: 'Yes. The C++ monitoring engine works fully offline. Cloud features (GeoIP lookup, threat intel updates, subscription validation) require internet but gracefully degrade when unavailable.' },
                                    { q: 'How do I unblock a false positive?', a: 'If NetSentinel blocked a legitimate connection, open Windows Firewall settings and delete the rule prefixed with "NetSentinel_Block_". Future versions will include a one-click unblock in the GUI.' },
                                    { q: 'Is the source code available?', a: 'NetSentinel is currently closed-source during the Beta period. An open-source community edition is under consideration for post-launch.' },
                                ].map(({ q, a }, i) => (
                                    <details key={i} className="glass-card group cursor-pointer">
                                        <summary className="flex items-center justify-between text-white font-medium list-none">
                                            <span>{q}</span>
                                            <ChevronRight className="h-4 w-4 text-slate-500 transition-transform group-open:rotate-90" />
                                        </summary>
                                        <p className="text-slate-400 text-sm mt-3 leading-relaxed">{a}</p>
                                    </details>
                                ))}
                            </div>
                        </Section>

                        {/* ─── FOOTER CTA ────────────────────────────────── */}
                        <div className="text-center mt-16 mb-8">
                            <div className="glass-card max-w-2xl mx-auto">
                                <h3 className="text-2xl font-bold text-white mb-3">Ready to secure your endpoint?</h3>
                                <p className="text-slate-400 mb-6">Download the free Beta and get 90 days of full protection.</p>
                                <div className="flex flex-col sm:flex-row gap-3 justify-center">
                                    <Link to="/register" className="px-8 py-3 rounded-full bg-gradient-to-r from-indigo-500 to-purple-600 text-white font-bold hover:from-indigo-400 hover:to-purple-500 transition-all shadow-lg shadow-indigo-500/30 flex items-center justify-center gap-2">
                                        Get Started Free <ChevronRight className="h-4 w-4" />
                                    </Link>
                                    <Link to="/pricing" className="px-8 py-3 rounded-full glass text-slate-200 font-medium hover:bg-slate-800/80 transition-all border border-slate-700">
                                        View Pricing
                                    </Link>
                                </div>
                            </div>
                        </div>

                    </main>
                </div>
            </div>

            {/* Scroll-to-top */}
            {showScrollTop && (
                <button
                    onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
                    className="fixed bottom-6 right-6 z-50 p-3 rounded-full bg-indigo-500 text-white shadow-lg shadow-indigo-500/40 hover:bg-indigo-400 transition-all animate-bounce"
                    aria-label="Scroll to top"
                >
                    <ArrowUp className="h-5 w-5" />
                </button>
            )}
        </div>
    );
};

export default DocsPage;
