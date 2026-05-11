import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

export default function App() {
  const [scans, setScans] = useState([]);

  // Fetch real data from the FastAPI backend
  const fetchHistory = async () => {
    try {
      const response = await axios.get('http://localhost:8000/history');
      setScans(response.data);
    } catch (error) {
      console.error("Backend offline or unreachable");
    }
  };

  // Run the fetch every 2 seconds to make it feel "live"
  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 2000);
    return () => clearInterval(interval);
  }, []);

  // Dynamically calculate the Pie Chart data based on real scans
  const safeCount = scans.filter(s => !s.is_malicious).length;
  const maliciousCount = scans.filter(s => s.is_malicious).length;
  const riskData = [
    { name: 'Safe', value: safeCount, color: '#16a34a' },
    { name: 'Malicious', value: maliciousCount, color: '#dc2626' }
  ];

// Function to generate and download a CSV report
  const exportIoCReport = () => {
    const headers = "Timestamp,Target URL,ML Flagged,VirusTotal Hits,Domain Age,Final Status\n";
    const csvRows = scans.map(scan => 
      `${scan.time},${scan.url},${scan.ml_flagged},${scan.vt_votes},${scan.domain_age},${scan.is_malicious ? 'MALICIOUS' : 'SAFE'}`
    );
    const blob = new Blob([headers + csvRows.join('\n')], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `PhishGuard_IoC_Report.csv`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 p-8 font-sans">
      
      {/* Header */}
      <div className="flex justify-between items-center mb-8 border-b border-slate-700 pb-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-wide">PhishGuard <span className="text-blue-500">SOC Dashboard</span></h1>
          <p className="text-slate-400 text-sm mt-1">Real-time Threat Intelligence & ML Diagnostics</p>
        </div>
        <button 
          onClick={exportIoCReport}
          className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-md font-semibold transition-all">
          Export IoC Report
        </button>
      </div>

      {/* Top Stats Cards */}
      <div className="grid grid-cols-3 gap-6 mb-8">
        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 shadow-lg">
          <h3 className="text-slate-400 font-semibold mb-2">Total URLs Scanned</h3>
          <p className="text-4xl font-bold text-white">{scans.length}</p>
        </div>
        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 shadow-lg">
          <h3 className="text-slate-400 font-semibold mb-2">Threats Blocked</h3>
          <p className="text-4xl font-bold text-red-500">{scans.filter(s => s.is_malicious).length}</p>
        </div>
        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 shadow-lg">
          <h3 className="text-slate-400 font-semibold mb-2">System Status</h3>
          <p className="text-2xl font-bold text-green-500 mt-2">Active & Monitoring</p>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-2 gap-6 mb-8">
        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 shadow-lg h-80">
          <h3 className="text-lg font-bold text-white mb-4">Risk Distribution</h3>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={riskData} cx="50%" cy="50%" innerRadius={60} outerRadius={100} paddingAngle={5} dataKey="value">
                {riskData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip cursor={{fill: 'transparent'}} contentStyle={{backgroundColor: '#1e293b', border: 'none', color: '#fff'}}/>
            </PieChart>
          </ResponsiveContainer>
        </div>
        
        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 shadow-lg h-80 flex flex-col justify-center items-center">
             <h3 className="text-lg font-bold text-white mb-4 w-full text-left">CTI Threat Vectors</h3>
             <p className="text-slate-400 text-center">Threat vector visualization will appear here as more URLs are processed by VirusTotal.</p>
        </div>
      </div>

      {/* Scan History Table */}
      <div className="bg-slate-800 rounded-lg border border-slate-700 shadow-lg overflow-hidden">
        <div className="p-6 border-b border-slate-700">
          <h3 className="text-lg font-bold text-white">Live Scan History</h3>
        </div>
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-900/50 text-slate-400 text-sm border-b border-slate-700">
              <th className="p-4 font-semibold">Timestamp</th>
              <th className="p-4 font-semibold">Target URL</th>
              <th className="p-4 font-semibold">ML Verdict</th>
              <th className="p-4 font-semibold">VirusTotal Hits</th>
              <th className="p-4 font-semibold">Domain Age (Days)</th>
              <th className="p-4 font-semibold text-right">Final Status</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id} className="border-b border-slate-700 hover:bg-slate-700/30 transition-colors">
                <td className="p-4 text-sm text-slate-400">{scan.time}</td>
                <td className="p-4 font-mono text-sm text-blue-400">{scan.url}</td>
                <td className="p-4 text-sm">{scan.ml_flagged ? '🚩 Flagged' : '✅ Clean'}</td>
                <td className="p-4 text-sm font-bold">{scan.vt_votes}</td>
                <td className="p-4 text-sm text-slate-300">
                  {scan.domain_age === -1 ? 'Unknown' : scan.domain_age}
                </td>
                <td className="p-4 text-right">
                  <span className={`px-3 py-1 rounded-full text-xs font-bold ${scan.is_malicious ? 'bg-red-500/20 text-red-500' : 'bg-green-500/20 text-green-500'}`}>
                    {scan.is_malicious ? 'MALICIOUS' : 'SAFE'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

    </div>
  );
}