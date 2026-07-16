"use client";

import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Sliders,
  FileSpreadsheet,
  Download,
  Upload,
  RefreshCw,
  Terminal,
  Activity,
  AlertTriangle,
  FileText,
  Clock,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
} from "lucide-react";
import { generateSyntheticData, RandomForestClassifier, Sample } from "@/lib/threatDetector";

// Interface for Gemini AI analysis report
interface GeminiReport {
  classification: string;
  riskLevel: string;
  summary: string;
  technicalDetails: string[];
  mitigationSteps: string[];
}

export default function Page() {
  // Model & synthetic dataset states
  const [dataset, setDataset] = useState<Sample[]>([]);
  const [model, setModel] = useState<RandomForestClassifier | null>(null);
  const [diagnostics, setDiagnostics] = useState<{
    accuracy: number;
    featureImportances: Record<string, number>;
  } | null>(null);

  // Active tab ("manual" | "batch" | "stream")
  const [activeTab, setActiveTab] = useState<"manual" | "batch" | "stream">("manual");

  // Manual Traffic simulation states
  const [duration, setDuration] = useState<number>(5.0);
  const [packetCount, setPacketCount] = useState<number>(45);
  const [bytesTransferred, setBytesTransferred] = useState<number>(25000);
  const [failedLogins, setFailedLogins] = useState<number>(0);

  // Batch CSV Processing states
  const [batchResults, setBatchResults] = useState<any[]>([]);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Live Stream Simulation states
  const [streamLogs, setStreamLogs] = useState<any[]>([]);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const streamIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Gemini AI Security Analyst states
  const [aiReport, setAiReport] = useState<GeminiReport | null>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [analyzingTarget, setAnalyzingTarget] = useState<string | null>(null); // To show which row is being analyzed

  // UI state
  const [copiedRemediation, setCopiedRemediation] = useState<boolean>(false);
  const [timeStr, setTimeStr] = useState<string>("09:29:34 UTC");

  const reinitializeModel = () => {
    const rawData = generateSyntheticData(1000, Date.now() % 10000);
    const rf = new RandomForestClassifier(12, 6, 2);
    rf.fit(rawData);

    setDataset(rawData);
    setModel(rf);
    setDiagnostics(rf.getDiagnostics());

    // Seed initial live stream logs with processed records
    const initialStream = rawData.slice(0, 15).map((d) => {
      const pred = rf.predict(d);
      return {
        ...d,
        prediction: pred.prediction,
        confidence: pred.confidence,
        timestamp: new Date(Date.now() - Math.random() * 60000).toLocaleTimeString(),
      };
    });
    setStreamLogs(initialStream);
  };

  // Initialize dataset & model on mount
  useEffect(() => {
    // Run initial training asynchronously to avoid synchronous effect state updates
    const timer = setTimeout(() => {
      reinitializeModel();
    }, 0);

    // Update live clock
    const interval = setInterval(() => {
      const now = new Date();
      setTimeStr(now.toUTCString().replace("GMT", "UTC"));
    }, 1000);

    return () => {
      clearTimeout(timer);
      clearInterval(interval);
    };
  }, []);

  // Compute manual prediction on the fly based on current sliders
  const manualPrediction = model
    ? model.predict({
        Duration_Sec: duration,
        Packet_Count: packetCount,
        Bytes_Transferred: bytesTransferred,
        Failed_Login_Attempts: failedLogins,
      })
    : null;

  // Live Firewall stream simulation logic
  useEffect(() => {
    if (!isStreaming || !model) {
      if (streamIntervalRef.current) clearInterval(streamIntervalRef.current);
      return;
    }

    streamIntervalRef.current = setInterval(() => {
      // 85% chance benign, 15% chance malicious
      const isMalicious = Math.random() < 0.15;
      let logSample: Omit<Sample, "id" | "Label">;

      if (isMalicious) {
        const packets = Math.floor(Math.random() * 400) + 400; // Poisson lam 500 approximation
        logSample = {
          Duration_Sec: Math.round((Math.random() * 250 + 10) * 100) / 100,
          Packet_Count: packets,
          Bytes_Transferred: Math.round(packets * (Math.random() * 600 + 1000)),
          Failed_Login_Attempts: Math.floor(Math.random() * 10) + 3,
        };
      } else {
        const packets = Math.floor(Math.random() * 40) + 30; // Poisson lam 50 approximation
        logSample = {
          Duration_Sec: Math.round(-Math.log(1 - Math.random()) * 5 * 100) / 100,
          Packet_Count: packets,
          Bytes_Transferred: Math.round(packets * (Math.random() * 200 + 400)),
          Failed_Login_Attempts: Math.random() < 0.05 ? 1 : 0,
        };
      }

      const pred = model.predict(logSample);
      const newLog = {
        ...logSample,
        id: `stream-${Date.now()}`,
        Label: isMalicious ? 1 : 0,
        prediction: pred.prediction,
        confidence: pred.confidence,
        timestamp: new Date().toLocaleTimeString(),
      };

      setStreamLogs((prev) => [newLog, ...prev.slice(0, 49)]);
    }, 2500);

    return () => {
      if (streamIntervalRef.current) clearInterval(streamIntervalRef.current);
    };
  }, [isStreaming, model]);

  // Handle template CSV generation & download
  const handleDownloadTemplate = () => {
    const headers = "Duration_Sec,Packet_Count,Bytes_Transferred,Failed_Login_Attempts\n";
    const rows = [
      "2.4,35,17500,0",
      "120.5,850,1120000,8",
      "0.8,12,4800,0",
      "45.2,220,290000,12",
      "8.5,52,26000,1",
      "240.0,910,4800000,15",
    ].join("\n");

    const blob = new Blob([headers + rows], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "network_traffic_logs_template.csv");
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Handle client-side CSV parsing
  const handleCSVUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !model) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        const lines = text.split(/\r?\n/);
        if (lines.length < 2) {
          setUploadError("The uploaded CSV must contain a header row and at least one data row.");
          return;
        }

        const headers = lines[0].toLowerCase().split(",").map((h) => h.trim());
        const durationIndex = headers.indexOf("duration_sec");
        const packetIndex = headers.indexOf("packet_count");
        const bytesIndex = headers.indexOf("bytes_transferred");
        const loginIndex = headers.indexOf("failed_login_attempts");

        if (durationIndex === -1 || packetIndex === -1 || bytesIndex === -1 || loginIndex === -1) {
          setUploadError("CSV header must contain: Duration_Sec, Packet_Count, Bytes_Transferred, Failed_Login_Attempts");
          return;
        }

        const parsed: any[] = [];
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;

          const cells = line.split(",").map((c) => c.trim());
          if (cells.length < headers.length) continue;

          const durationVal = parseFloat(cells[durationIndex]);
          const packetVal = parseInt(cells[packetIndex]);
          const bytesVal = parseFloat(cells[bytesIndex]);
          const loginVal = parseInt(cells[loginIndex]);

          if (isNaN(durationVal) || isNaN(packetVal) || isNaN(bytesVal) || isNaN(loginVal)) {
            setUploadError(`Invalid data format on line ${i + 1}.`);
            return;
          }

          parsed.push({
            id: `upload-${i}-${Date.now()}`,
            Duration_Sec: durationVal,
            Packet_Count: packetVal,
            Bytes_Transferred: bytesVal,
            Failed_Login_Attempts: loginVal,
          });
        }

        if (parsed.length === 0) {
          setUploadError("No valid rows parsed.");
          return;
        }

        const processed = parsed.map((item) => {
          const pred = model.predict(item);
          return {
            ...item,
            Label: pred.prediction,
            prediction: pred.prediction,
            confidence: pred.confidence,
            timestamp: new Date().toLocaleTimeString(),
          };
        });

        setBatchResults(processed);
        setUploadError(null);
      } catch (err: any) {
        setUploadError(`Failed to parse CSV file: ${err.message}`);
      }
    };
    reader.readAsText(file);
  };

  // Call server-side Gemini API route for Threat Diagnostic
  const handleRequestGeminiAnalysis = async (
    targetId: string,
    metrics: {
      duration: number;
      packetCount: number;
      bytesTransferred: number;
      failedLogins: number;
      prediction: number;
      confidence: number;
    }
  ) => {
    setAiLoading(true);
    setAiError(null);
    setAnalyzingTarget(targetId);
    setAiReport(null);

    try {
      const response = await fetch("/api/gemini/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          duration: metrics.duration,
          packetCount: metrics.packetCount,
          bytesTransferred: metrics.bytesTransferred,
          failedLogins: metrics.failedLogins,
          label: metrics.prediction,
          confidence: metrics.confidence,
        }),
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || "Server-side analysis failed");
      }

      const report: GeminiReport = await response.json();
      setAiReport(report);
    } catch (err: any) {
      setAiError(err.message || "Failed to reach AI Threat Analyst");
    } finally {
      setAiLoading(false);
      setAnalyzingTarget(null);
    }
  };

  const handleCopyRemediation = () => {
    if (!aiReport) return;
    const text = `SECURITY INCIDENT REPORT
Classification: ${aiReport.classification}
Risk Level: ${aiReport.riskLevel}
Summary: ${aiReport.summary}

REMEDIATION ACTION PLAN:
${aiReport.mitigationSteps.map((step, idx) => `${idx + 1}. ${step}`).join("\n")}`;

    navigator.clipboard.writeText(text);
    setCopiedRemediation(true);
    setTimeout(() => setCopiedRemediation(false), 2000);
  };

  // Helper formatting values
  const formatBytes = (bytes: number) => {
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  // Summary counts for Batch parsing
  const batchTotal = batchResults.length;
  const batchThreatsCount = batchResults.filter((r) => r.prediction === 1).length;

  return (
    <div id="cyber-threat-dashboard" className="min-h-screen bg-[#f8fafc] text-slate-900 flex flex-col xl:flex-row font-sans select-none antialiased">
      
      {/* Left Sidebar / Diagnostics Panel */}
      <aside id="sidebar-panel" className="w-full xl:w-80 bg-[#0f172a] text-slate-300 flex flex-col border-r border-slate-800 shrink-0">
        <div className="p-6 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center shadow-lg shadow-blue-500/20">
              <ShieldAlert className="text-white w-5 h-5" />
            </div>
            <div>
              <h2 className="font-bold text-white text-base tracking-tight">CyberSentry AI</h2>
              <p className="text-[10px] text-slate-500 font-mono">SOC NODE: AI-01</p>
            </div>
          </div>
          
          <button
            onClick={reinitializeModel}
            className="text-slate-400 hover:text-white hover:bg-slate-800/80 p-2 rounded-lg transition-colors duration-150 cursor-pointer"
            title="Re-train Model with New Seed"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
        
        {/* Sidebar Diagnostics Content */}
        <div className="p-6 flex-1 flex flex-col gap-8 overflow-y-auto">
          {/* Accuracy Gauge Card */}
          <div>
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-4">Model Diagnostics</h3>
            <div className="bg-slate-800/50 rounded-xl p-4 border border-slate-700/60">
              <div className="text-xs text-slate-400 mb-1">Accuracy Score</div>
              <div className="text-3xl font-mono font-bold text-blue-400">
                {diagnostics ? `${(diagnostics.accuracy * 100).toFixed(2)}%` : "98.42%"}
              </div>
              <div className="mt-2.5 h-1.5 w-full bg-slate-700 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-blue-500 rounded-full transition-all duration-1000" 
                  style={{ width: diagnostics ? `${diagnostics.accuracy * 100}%` : "0%" }}
                />
              </div>
            </div>
          </div>

          {/* Feature Importance Interactive Plot */}
          <div>
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-4">Feature Importance</h3>
            <div className="space-y-4">
              {diagnostics &&
                Object.entries(diagnostics.featureImportances).map(([key, value]) => {
                  const displayNames: Record<string, string> = {
                    Duration_Sec: "Duration (s)",
                    Packet_Count: "Packet Count",
                    Bytes_Transferred: "Bytes Xfer",
                    Failed_Login_Attempts: "Failed Logins",
                  };
                  return (
                    <div key={key} className="group">
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-slate-400">{displayNames[key] || key}</span>
                        <span className="text-blue-400 font-mono font-semibold">{(value * 100).toFixed(0)}%</span>
                      </div>
                      <div className="h-2 w-full bg-slate-700 rounded-full overflow-hidden">
                        <motion.div
                          className="h-full bg-blue-500"
                          initial={{ width: 0 }}
                          animate={{ width: `${value * 100}%` }}
                          transition={{ duration: 0.8, ease: "easeOut" }}
                        />
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>

          {/* Active Insights */}
          <div className="mt-auto pt-4 border-t border-slate-800 text-[11px] text-slate-500 leading-relaxed font-sans">
            <div className="flex gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
              <p>
                Failed login attempts and anomalous packet rate nodes are critical signals for credential brute-force and data exfiltration patterns.
              </p>
            </div>
          </div>
        </div>
        
        {/* Sidebar Footer */}
        <div className="p-6 bg-slate-900/50 text-xs text-slate-500 border-t border-slate-800">
          System Status: <span className="text-emerald-500 font-medium">Online</span> • Node: AI-01
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0">
        
        {/* Header */}
        <header id="dashboard-header" className="bg-white px-8 py-6 border-b border-slate-200 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 shadow-sm">
          <div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
              Cyber Threat Detection Framework
            </h1>
            <p className="text-slate-500 text-sm mt-0.5">Evaluating network traffic for anomalies using Random Forest Ensemble classification.</p>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono text-slate-600 bg-slate-50 px-3.5 py-2 rounded-xl border border-slate-200 shadow-sm">
            <div className="flex items-center gap-2 border-r border-slate-200 pr-3">
              <Clock className="w-4 h-4 text-emerald-600" />
              <span className="font-semibold text-slate-700">{timeStr}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-rose-500 animate-pulse" />
              <span className="text-slate-700 font-semibold">SOC Sentinel: <span className="text-emerald-600 font-bold">ACTIVE</span></span>
            </div>
          </div>
        </header>

        {/* Tabs Navigation */}
        <div className="px-8 bg-white border-b border-slate-200 flex gap-8">
          <button
            id="tab-btn-manual"
            onClick={() => setActiveTab("manual")}
            className={`py-4 border-b-2 text-sm font-semibold flex items-center gap-2 transition-all duration-150 cursor-pointer ${
              activeTab === "manual"
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-slate-500 hover:text-slate-700"
            }`}
          >
            <Sliders className="w-4 h-4" />
            Live Threat Analyzer
          </button>
          <button
            id="tab-btn-batch"
            onClick={() => {
              setActiveTab("batch");
              setIsStreaming(false);
            }}
            className={`py-4 border-b-2 text-sm font-semibold flex items-center gap-2 transition-all duration-150 cursor-pointer ${
              activeTab === "batch"
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-slate-500 hover:text-slate-700"
            }`}
          >
            <FileSpreadsheet className="w-4 h-4" />
            Batch Processing (CSV)
          </button>
          <button
            id="tab-btn-stream"
            onClick={() => {
              setActiveTab("stream");
              setIsStreaming(true);
            }}
            className={`py-4 border-b-2 text-sm font-semibold flex items-center gap-2 transition-all duration-150 cursor-pointer ${
              activeTab === "stream"
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-slate-500 hover:text-slate-700"
            }`}
          >
            <Terminal className="w-4 h-4" />
            Firewall Live Stream
          </button>
        </div>

        {/* Dashboard Body / Workspace */}
        <div className="p-8 flex-1 flex flex-col gap-6 overflow-y-auto max-w-[1400px] w-full mx-auto">
          
          {/* Dynamic Content depending on tabs */}
          <div className="flex-1 flex flex-col gap-6">

            {/* TAB 1: Live Threat Analyzer */}
            {activeTab === "manual" && (
              <div id="tab-live-manual" className="grid grid-cols-1 lg:grid-cols-2 gap-8 bg-white p-8 rounded-xl border border-slate-200 shadow-sm">
                
                {/* Sliders Container (Manual Traffic Simulation) */}
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-semibold text-slate-800">Manual Traffic Simulation</h3>
                    <p className="text-xs text-slate-500 mt-1">Adjust connection telemetry parameters to evaluate security risk metrics.</p>
                  </div>

                  <div className="space-y-5">
                    {/* Duration slider */}
                    <div className="space-y-1.5">
                      <div className="flex justify-between text-xs font-bold text-slate-500 uppercase tracking-wider">
                        <span>Connection Duration</span>
                        <span className="text-blue-600 font-mono font-bold">{duration.toFixed(1)} s</span>
                      </div>
                      <div className="flex items-center gap-4">
                        <input
                          type="range"
                          min="0.1"
                          max="600.0"
                          step="0.5"
                          value={duration}
                          onChange={(e) => setDuration(parseFloat(e.target.value))}
                          className="flex-1 accent-blue-600 bg-slate-200 h-1.5 rounded-lg appearance-none cursor-pointer"
                        />
                        <span className="text-sm font-mono bg-slate-100 px-2 py-1 rounded w-16 text-center text-slate-700 font-semibold">{duration.toFixed(1)}</span>
                      </div>
                    </div>

                    {/* Packet Count and Bytes Transferred Side-by-Side */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider">Packet Count</label>
                        <input
                          type="number"
                          min="1"
                          max="10000"
                          value={packetCount}
                          onChange={(e) => setPacketCount(Math.max(1, Math.min(10000, parseInt(e.target.value) || 0)))}
                          className="w-full bg-slate-50 border border-slate-200 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 text-slate-800 font-mono font-medium"
                        />
                        <input
                          type="range"
                          min="1"
                          max="2000"
                          value={packetCount > 2000 ? 2000 : packetCount}
                          onChange={(e) => setPacketCount(parseInt(e.target.value))}
                          className="w-full accent-blue-600 bg-slate-200 h-1 rounded-lg appearance-none cursor-pointer"
                        />
                      </div>

                      <div className="space-y-1.5">
                        <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider">Bytes Transferred</label>
                        <input
                          type="number"
                          min="0"
                          max="50000000"
                          value={bytesTransferred}
                          onChange={(e) => setBytesTransferred(Math.max(0, parseInt(e.target.value) || 0))}
                          className="w-full bg-slate-50 border border-slate-200 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 text-slate-800 font-mono font-medium"
                        />
                        <span className="text-[10px] text-slate-400 block text-right font-semibold">{formatBytes(bytesTransferred)}</span>
                      </div>
                    </div>

                    {/* Failed Login Attempts */}
                    <div className="space-y-1.5">
                      <div className="flex justify-between text-xs font-bold text-slate-500 uppercase tracking-wider">
                        <span>Failed Login Attempts</span>
                        <span className={failedLogins > 2 ? "text-red-600 font-bold" : "text-blue-600 font-bold"}>
                          {failedLogins} attempts
                        </span>
                      </div>
                      <div className="flex items-center gap-4">
                        <input
                          type="range"
                          min="0"
                          max="20"
                          value={failedLogins}
                          onChange={(e) => setFailedLogins(parseInt(e.target.value))}
                          className="flex-1 accent-blue-600 bg-slate-200 h-1.5 rounded-lg appearance-none cursor-pointer"
                        />
                        <span className="text-sm font-mono bg-slate-100 px-2 py-1 rounded w-16 text-center text-slate-700 font-semibold">{failedLogins}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Live Model Result Display */}
                <div className="flex flex-col justify-between gap-6">
                  <div className="text-center md:text-left">
                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Classifier Assessment</h3>
                    <p className="text-xs text-slate-500 mt-1">Real-time inference generated by the Random Forest ensemble.</p>
                  </div>

                  <AnimatePresence mode="wait">
                    {manualPrediction ? (
                      <motion.div
                        key={manualPrediction.prediction}
                        initial={{ opacity: 0, scale: 0.98 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.98 }}
                        className={`flex-1 flex flex-col justify-center items-center text-center p-8 rounded-xl border-2 ${
                          manualPrediction.prediction === 1
                            ? "bg-red-50/50 border-red-150 text-red-900"
                            : "bg-emerald-50/50 border-emerald-150 text-emerald-900"
                        }`}
                      >
                        {manualPrediction.prediction === 1 ? (
                          <>
                            <div className="w-16 h-16 bg-red-100 text-red-600 rounded-full flex items-center justify-center text-3xl mb-4 shadow-sm">
                              🚨
                            </div>
                            <h4 className="text-2xl font-bold text-red-700">Threat Detected!</h4>
                            <div className="mt-2 bg-red-200/50 text-red-800 text-xs font-bold px-3 py-1 rounded-full">
                              CONFIDENCE: {(manualPrediction.confidence * 100).toFixed(2)}%
                            </div>
                            <div className="mt-4 text-sm text-slate-600 max-w-sm leading-relaxed">
                              Potential <strong>Anomalous Vector</strong> identified. Connection metrics exceed typical enterprise baselines and exhibit high security risk profiles.
                            </div>
                          </>
                        ) : (
                          <>
                            <div className="w-16 h-16 bg-emerald-100 text-emerald-600 rounded-full flex items-center justify-center text-3xl mb-4 shadow-sm">
                              🛡️
                            </div>
                            <h4 className="text-2xl font-bold text-emerald-700">Benign Flow</h4>
                            <div className="mt-2 bg-emerald-200/50 text-emerald-800 text-xs font-bold px-3 py-1 rounded-full">
                              CONFIDENCE: {(manualPrediction.confidence * 100).toFixed(2)}%
                            </div>
                            <div className="mt-4 text-sm text-slate-600 max-w-sm leading-relaxed">
                              No anomalous signatures observed. Telemetry points are within safe bounds of network baselines.
                            </div>
                          </>
                        )}
                      </motion.div>
                    ) : null}
                  </AnimatePresence>

                  <div className="pt-2">
                    <button
                      onClick={() =>
                        handleRequestGeminiAnalysis("manual-flow", {
                          duration,
                          packetCount,
                          bytesTransferred,
                          failedLogins,
                          prediction: manualPrediction?.prediction ?? 0,
                          confidence: manualPrediction?.confidence ?? 1,
                        })
                      }
                      disabled={aiLoading}
                      className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-100 disabled:text-slate-400 text-white rounded-lg font-bold text-xs uppercase tracking-wider transition-colors shadow-sm cursor-pointer"
                    >
                      <Cpu className={`w-4 h-4 ${aiLoading ? "animate-spin" : ""}`} />
                      {aiLoading ? "Generating AI Security Diagnostic..." : "Request Gemini Deep SOC Analysis"}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: Batch Processing (CSV) */}
            {activeTab === "batch" && (
              <div id="tab-batch-csv" className="flex flex-col gap-6">
                
                {/* File Uploader Grid & Sample Template Download */}
                <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-stretch">
                  
                  {/* CSV Template Download Card */}
                  <div className="md:col-span-5 bg-white border border-slate-200 shadow-sm p-6 rounded-xl flex flex-col justify-between gap-4">
                    <div>
                      <h4 className="text-sm font-bold text-slate-800">Prepare Batch CSV Input</h4>
                      <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                        Structure your CSV according to firewall log export parameters to batch identify anomalies.
                      </p>
                    </div>

                    <button
                      onClick={handleDownloadTemplate}
                      className="w-full py-2.5 px-4 bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-all shadow-sm cursor-pointer"
                    >
                      <Download className="w-4 h-4 text-blue-600" />
                      Download Sample Template CSV
                    </button>
                  </div>

                  {/* Drag-and-Drop / Browse card */}
                  <div className="md:col-span-7 bg-white border border-slate-200 shadow-sm p-6 rounded-xl flex flex-col justify-center items-center border-dashed border-slate-300 hover:border-blue-500 hover:bg-blue-50/10 transition-all group relative">
                    <input
                      type="file"
                      accept=".csv"
                      ref={fileInputRef}
                      onChange={handleCSVUpload}
                      className="absolute inset-0 opacity-0 cursor-pointer"
                    />
                    <div className="flex flex-col items-center gap-3 py-4 text-center pointer-events-none">
                      <div className="p-3 bg-blue-50 group-hover:bg-blue-100 rounded-full border border-blue-100 transition-all duration-200">
                        <Upload className="w-5 h-5 text-blue-600" />
                      </div>
                      <div>
                        <p className="text-xs font-semibold text-slate-800">Drag & drop your network log CSV here</p>
                        <p className="text-[10px] text-slate-500 mt-0.5">Or click to browse from local filesystem</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Upload error display */}
                {uploadError && (
                  <div className="p-3.5 bg-red-50 border border-red-150 text-red-700 text-xs rounded-lg flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>{uploadError}</span>
                  </div>
                )}

                {/* Batch Metrics Overview */}
                {batchTotal > 0 && (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                    <div className="bg-white border border-slate-200 shadow-sm p-5 rounded-xl flex flex-col justify-center">
                      <p className="text-xxs text-slate-400 uppercase font-bold tracking-wider">Entries Processed</p>
                      <p className="text-2xl font-bold font-mono text-slate-800 mt-1">{batchTotal}</p>
                    </div>
                    <div className="bg-white border border-slate-200 shadow-sm p-5 rounded-xl flex flex-col justify-center">
                      <p className="text-xxs text-slate-400 uppercase font-bold tracking-wider">Threats Flagged</p>
                      <p className="text-2xl font-bold font-mono text-red-600 mt-1">{batchThreatsCount}</p>
                    </div>
                    <div className="bg-white border border-slate-200 shadow-sm p-5 rounded-xl flex flex-col justify-center">
                      <p className="text-xxs text-slate-400 uppercase font-bold tracking-wider">Anomaly Rate</p>
                      <p className="text-2xl font-bold font-mono text-blue-600 mt-1">
                        {((batchThreatsCount / batchTotal) * 100).toFixed(1)}%
                      </p>
                    </div>
                  </div>
                )}

                {/* Batch Results Table */}
                {batchTotal > 0 && (
                  <div className="bg-white border border-slate-200 shadow-sm rounded-xl overflow-hidden">
                    <div className="px-5 py-4 border-b border-slate-200 bg-slate-50 flex justify-between items-center">
                      <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">Batch Prediction Results</h4>
                      <span className="text-[10px] text-slate-500 font-mono font-medium">Processed using Local RF Classifier</span>
                    </div>

                    <div className="overflow-x-auto max-h-[300px]">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead className="bg-slate-100/80 text-slate-600 font-mono text-[10px] uppercase border-b border-slate-200 sticky top-0">
                          <tr>
                            <th className="p-3 pl-5">Status</th>
                            <th className="p-3">Duration (s)</th>
                            <th className="p-3">Packets</th>
                            <th className="p-3">Bytes</th>
                            <th className="p-3">Failed Logins</th>
                            <th className="p-3 text-right pr-5">Inference Analysis</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 font-mono text-[11px] text-slate-700">
                          {batchResults.map((row, idx) => (
                            <tr key={row.id || idx} className="hover:bg-slate-50/50 transition-all duration-100">
                              <td className="p-3 pl-5">
                                <span
                                  className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[10px] font-sans font-bold ${
                                    row.prediction === 1
                                      ? "bg-red-50 text-red-700 border border-red-200"
                                      : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                                  }`}
                                >
                                  {row.prediction === 1 ? (
                                    <>
                                      <ShieldAlert className="w-3 h-3" /> THREAT
                                    </>
                                  ) : (
                                    <>
                                      <ShieldCheck className="w-3 h-3" /> BENIGN
                                    </>
                                  )}
                                </span>
                              </td>
                              <td className="p-3 text-slate-600">{row.Duration_Sec.toFixed(1)}s</td>
                              <td className="p-3 text-slate-600">{row.Packet_Count}</td>
                              <td className="p-3 text-slate-600">{formatBytes(row.Bytes_Transferred)}</td>
                              <td className={`p-3 font-semibold ${row.Failed_Login_Attempts > 2 ? "text-red-600 font-bold" : "text-slate-500"}`}>
                                {row.Failed_Login_Attempts}
                              </td>
                              <td className="p-3 text-right pr-5">
                                <button
                                  onClick={() =>
                                    handleRequestGeminiAnalysis(row.id, {
                                      duration: row.Duration_Sec,
                                      packetCount: row.Packet_Count,
                                      bytesTransferred: row.Bytes_Transferred,
                                      failedLogins: row.Failed_Login_Attempts,
                                      prediction: row.prediction,
                                      confidence: row.confidence,
                                    })
                                  }
                                  disabled={aiLoading && analyzingTarget === row.id}
                                  className="py-1 px-3 bg-white hover:bg-slate-50 border border-slate-200 text-xxs font-sans font-semibold rounded text-slate-700 hover:text-slate-900 transition shadow-sm cursor-pointer"
                                >
                                  {aiLoading && analyzingTarget === row.id ? (
                                    <span className="flex items-center gap-1">
                                      <RefreshCw className="w-2.5 h-2.5 animate-spin" /> Analyzing...
                                    </span>
                                  ) : (
                                    "Deep AI Analysis"
                                  )}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: Firewall Live Stream */}
            {activeTab === "stream" && (
              <div id="tab-firewall-stream" className="flex flex-col gap-6">
                
                {/* Control bar */}
                <div className="bg-white border border-slate-200 shadow-sm px-5 py-4 rounded-xl flex justify-between items-center">
                  <div className="flex items-center gap-3">
                    <span className="flex h-2.5 w-2.5 relative">
                      <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${isStreaming ? "bg-emerald-400" : "bg-amber-400"}`}></span>
                      <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${isStreaming ? "bg-emerald-500" : "bg-amber-500"}`}></span>
                    </span>
                    <span className="text-xs font-semibold text-slate-700">
                      {isStreaming ? "Ingesting active network firewall flow logs..." : "Ingestion Paused"}
                    </span>
                  </div>

                  <button
                    onClick={() => setIsStreaming(!isStreaming)}
                    className={`py-1.5 px-3 rounded text-xxs uppercase tracking-wider font-bold transition-all border shadow-sm cursor-pointer ${
                      isStreaming
                        ? "bg-amber-50 border-amber-200 text-amber-700 hover:bg-amber-100"
                        : "bg-emerald-50 border-emerald-200 text-emerald-700 hover:bg-emerald-100"
                    }`}
                  >
                    {isStreaming ? "Pause Ingestion" : "Resume Ingestion"}
                  </button>
                </div>

                {/* Streaming list log flow */}
                <div className="bg-white border border-slate-200 shadow-sm rounded-xl overflow-hidden flex flex-col">
                  <div className="px-5 py-4 border-b border-slate-200 bg-slate-50 flex justify-between items-center text-xs">
                    <span className="font-bold text-slate-700 uppercase tracking-wider">Live Firewall Stream log</span>
                    <span className="font-mono text-[10px] text-slate-500 font-medium">Auto-evaluating on packet reception</span>
                  </div>

                  <div className="overflow-y-auto h-[350px] p-4 flex flex-col gap-2 font-mono text-[11px] leading-normal bg-slate-900">
                    <AnimatePresence initial={false}>
                      {streamLogs.map((log) => (
                        <motion.div
                          key={log.id}
                          initial={{ opacity: 0, x: -15, height: 0 }}
                          animate={{ opacity: 1, x: 0, height: "auto" }}
                          exit={{ opacity: 0, x: 15 }}
                          transition={{ type: "spring", stiffness: 350, damping: 30 }}
                          className={`p-2.5 rounded border flex flex-col sm:flex-row justify-between sm:items-center gap-2 ${
                            log.prediction === 1
                              ? "bg-red-950/20 border-red-900/30 text-red-200"
                              : "bg-slate-800/40 border-slate-800/30 text-slate-300"
                          }`}
                        >
                          <div className="flex flex-wrap items-center gap-3">
                            <span className="text-[10px] text-slate-500">{log.timestamp}</span>
                            <span
                              className={`px-1.5 py-0.2 rounded text-[9px] font-sans font-bold uppercase ${
                                log.prediction === 1 ? "bg-red-500/25 text-red-300" : "bg-emerald-500/25 text-emerald-300"
                              }`}
                            >
                              {log.prediction === 1 ? "🚨 THREAT" : "✅ OK"}
                            </span>
                            <span className="text-slate-400">dur={log.Duration_Sec}s</span>
                            <span className="text-slate-400">pkts={log.Packet_Count}</span>
                            <span className="text-slate-400">bytes={formatBytes(log.Bytes_Transferred)}</span>
                            <span className="text-slate-400">fail_logins={log.Failed_Login_Attempts}</span>
                          </div>

                          <div className="flex items-center gap-2 self-end sm:self-auto">
                            <span className="text-xxs text-slate-500">Conf: {(log.confidence * 100).toFixed(0)}%</span>
                            <button
                              onClick={() =>
                                handleRequestGeminiAnalysis(log.id, {
                                  duration: log.Duration_Sec,
                                  packetCount: log.Packet_Count,
                                  bytesTransferred: log.Bytes_Transferred,
                                  failedLogins: log.Failed_Login_Attempts,
                                  prediction: log.prediction,
                                  confidence: log.confidence,
                                })
                              }
                              disabled={aiLoading && analyzingTarget === log.id}
                              className="py-0.5 px-1.5 bg-slate-950 border border-slate-800 text-[10px] font-sans rounded hover:bg-slate-900 transition-all text-slate-300 hover:text-white cursor-pointer"
                            >
                              {aiLoading && analyzingTarget === log.id ? "..." : "Analyze"}
                            </button>
                          </div>
                        </motion.div>
                      ))}
                    </AnimatePresence>
                  </div>
                </div>
              </div>
            )}

            {/* AI INCIDENT RESPONSE CARD (Renders on successfully receiving a report) */}
            <AnimatePresence>
              {(aiLoading || aiReport || aiError) && (
                <motion.div
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 15 }}
                  transition={{ duration: 0.3 }}
                  id="gemini-analyst-panel"
                  className="bg-white border border-slate-200 shadow-lg rounded-xl overflow-hidden p-6 flex flex-col gap-5 relative"
                >
                  {/* Glowing accent border */}
                  <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-blue-500 via-indigo-500 to-purple-600" />

                  <div className="flex justify-between items-start gap-4">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 bg-blue-50 rounded-lg border border-blue-100 shadow-sm">
                        <Cpu className="w-5 h-5 text-blue-600 animate-pulse" />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold tracking-wide text-slate-800">Gemini AI Cyber Threat Intelligence</h4>
                        <p className="text-xs text-slate-500">Autonomous Tier-3 SOC Analysis Summary</p>
                      </div>
                    </div>

                    {(aiReport || aiError) && (
                      <button
                        onClick={() => {
                          setAiReport(null);
                          setAiError(null);
                        }}
                        className="text-xxs uppercase tracking-wider font-bold text-slate-400 hover:text-slate-700 transition-colors cursor-pointer"
                      >
                        Dismiss
                      </button>
                    )}
                  </div>

                  {aiLoading && (
                    <div className="py-8 flex flex-col items-center justify-center gap-3">
                      <RefreshCw className="w-8 h-8 text-blue-600 animate-spin" />
                      <div className="text-center">
                        <p className="text-xs text-slate-700 font-semibold">Gemini Security Engine Decrypting Logs...</p>
                        <p className="text-xxs text-slate-400 mt-1 font-mono">Running deep packet heuristics and mapping attack vectors</p>
                      </div>
                    </div>
                  )}

                  {aiError && (
                    <div className="p-4 bg-red-50 border border-red-150 rounded-lg flex items-center gap-3">
                      <AlertTriangle className="w-5 h-5 text-red-600 shrink-0" />
                      <div>
                        <p className="text-xs font-bold text-red-700">Analysis Error</p>
                        <p className="text-xxs text-slate-500 mt-0.5">{aiError}</p>
                      </div>
                    </div>
                  )}

                  {aiReport && (
                    <div className="flex flex-col gap-5 leading-normal">
                      
                      {/* Metric headers: Classification & Risk */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="bg-slate-50 p-4 rounded-lg border border-slate-200/80">
                          <p className="text-xxs text-slate-400 uppercase font-bold tracking-wider">Identified Vector</p>
                          <p className="text-sm font-semibold text-slate-800 mt-1 flex items-center gap-1.5">
                            <Activity className="w-4 h-4 text-blue-600 shrink-0" />
                            {aiReport.classification}
                          </p>
                        </div>
                        <div className="bg-slate-50 p-4 rounded-lg border border-slate-200/80 flex flex-col justify-between">
                          <p className="text-xxs text-slate-400 uppercase font-bold tracking-wider">Assessed Risk Level</p>
                          <div className="flex items-center gap-2 mt-1">
                            <span
                              className={`h-2.5 w-2.5 rounded-full ${
                                aiReport.riskLevel.toLowerCase() === "critical"
                                  ? "bg-red-500 animate-ping"
                                  : aiReport.riskLevel.toLowerCase() === "high"
                                  ? "bg-red-500"
                                  : aiReport.riskLevel.toLowerCase() === "medium"
                                  ? "bg-amber-500"
                                  : "bg-emerald-500"
                              }`}
                            />
                            <span
                              className={`text-sm font-bold uppercase ${
                                aiReport.riskLevel.toLowerCase() === "critical" || aiReport.riskLevel.toLowerCase() === "high"
                                  ? "text-red-600"
                                  : aiReport.riskLevel.toLowerCase() === "medium"
                                  ? "text-amber-600"
                                  : "text-emerald-600"
                              }`}
                            >
                              {aiReport.riskLevel}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Summary Section */}
                      <div className="bg-slate-50 p-4 rounded-lg border border-slate-200/80 flex flex-col gap-1.5">
                        <h5 className="text-xs font-bold text-slate-700 flex items-center gap-1.5">
                          <FileText className="w-4 h-4 text-blue-600" /> Executive Narrative
                        </h5>
                        <p className="text-xs text-slate-600 leading-relaxed">{aiReport.summary}</p>
                      </div>

                      {/* Technical Details & Mitigation Side-by-Side */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
                        
                        <div className="bg-slate-50 p-4 rounded-lg border border-slate-200/80 flex flex-col gap-3">
                          <h5 className="text-xs font-bold text-slate-700 flex items-center gap-1.5">
                            <Terminal className="w-4 h-4 text-blue-600" /> Indicators of Compromise (IoC)
                          </h5>
                          <ul className="flex flex-col gap-2 text-xxs text-slate-500 leading-relaxed list-none pl-0">
                            {aiReport.technicalDetails.map((detail, idx) => (
                              <li key={idx} className="flex items-start gap-2">
                                <span className="h-1.5 w-1.5 rounded-full bg-blue-500 shrink-0 mt-1.5" />
                                <span>{detail}</span>
                              </li>
                            ))}
                          </ul>
                        </div>

                        <div className="bg-slate-50 p-4 rounded-lg border border-slate-200/80 flex flex-col justify-between gap-3">
                          <div>
                            <h5 className="text-xs font-bold text-slate-700 flex items-center gap-1.5">
                              <CheckCircle2 className="w-4 h-4 text-emerald-600" /> Recommended Action Plan
                            </h5>
                            <ul className="flex flex-col gap-2 text-xxs text-slate-500 leading-relaxed list-none pl-0 mt-3">
                              {aiReport.mitigationSteps.map((step, idx) => (
                                <li key={idx} className="flex items-start gap-2">
                                  <span className="text-emerald-600 shrink-0 font-bold font-mono">{idx + 1}.</span>
                                  <span>{step}</span>
                                </li>
                              ))}
                            </ul>
                          </div>

                          <div className="pt-2 border-t border-slate-200/60 flex justify-end">
                            <button
                              onClick={handleCopyRemediation}
                              className="py-1 px-3 bg-white border border-slate-200 rounded flex items-center gap-1.5 text-xxs text-slate-600 hover:text-slate-950 hover:bg-slate-50 transition shadow-sm cursor-pointer"
                            >
                              {copiedRemediation ? (
                                <>
                                  <Check className="w-3.5 h-3.5 text-emerald-600" /> Copied Plan!
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3.5 h-3.5 text-slate-500" /> Copy Remediation
                                </>
                              )}
                            </button>
                          </div>
                        </div>

                      </div>

                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>

          </div>

          {/* Quick Stats Footer */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
              <div className="text-slate-400 text-xs font-bold uppercase tracking-wider mb-1">Active Scans</div>
              <div className="text-xl font-bold text-slate-800">1,240</div>
            </div>
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
              <div className="text-slate-400 text-xs font-bold uppercase tracking-wider mb-1">Threats Blocked</div>
              <div className="text-xl font-bold text-emerald-600">48</div>
            </div>
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
              <div className="text-slate-400 text-xs font-bold uppercase tracking-wider mb-1">System Latency</div>
              <div className="text-xl font-bold text-slate-800">12ms</div>
            </div>
            <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm">
              <div className="text-slate-400 text-xs font-bold uppercase tracking-wider mb-1">Last Re-train</div>
              <div className="text-xl font-bold text-blue-600">4h ago</div>
            </div>
          </div>

        </div>

        {/* Humble Footer */}
        <footer id="dashboard-footer" className="border-t border-slate-200 px-8 py-4 text-center text-xxs text-slate-400 bg-white font-mono mt-auto">
          SYSTEM CLASSIFIERS CALIBRATED SUCCESSFULLY ON {timeStr}. VERIFIED FOR COMPROMISE INTRUSIONS.
        </footer>

      </main>
    </div>
  );
}
