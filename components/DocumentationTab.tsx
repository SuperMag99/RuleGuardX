import React from 'react';
import { BookOpen, Shield, Target, Zap, Layers, Activity, Info, ExternalLink } from 'lucide-react';

const DocumentationTab: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto space-y-12 animate-in fade-in duration-700">
      <div className="space-y-4">
        <h2 className="text-3xl font-black text-white flex items-center gap-3">
          <BookOpen className="w-8 h-8 text-indigo-500" /> Audit Methodology & Knowledge Base
        </h2>
        <p className="text-slate-400 leading-relaxed text-lg">
          RuleGuardX is designed to provide enterprise-grade, defensible firewall audits. It evaluates rules not just as static lines of configuration, 
          but as potential exploit vectors mapped to modern security frameworks.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <section className="bg-slate-900/50 border border-slate-800 p-6 rounded-2xl space-y-4">
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <Target className="w-5 h-5 text-indigo-400" /> Risk Scoring Model (0-100)
          </h3>
          <div className="space-y-4 text-sm text-slate-300">
            <p>The <strong>Policy Risk Score</strong> is a weighted average of individual rule findings. Each finding is assigned a numerical value based on its exploitation potential:</p>
            <ul className="space-y-2">
              <li className="flex gap-2">
                <span className="text-red-500 font-bold w-12 shrink-0">100</span>
                <span><strong>Critical:</strong> Broad ANY/ANY rules or direct internet exposure of administrative ports (RDP/SSH).</span>
              </li>
              <li className="flex gap-2">
                <span className="text-orange-500 font-bold w-12 shrink-0">80+</span>
                <span><strong>High:</strong> Large subnet scopes (/16 or larger) or usage of legacy protocols like Telnet/FTP.</span>
              </li>
              <li className="flex gap-2">
                <span className="text-yellow-500 font-bold w-12 shrink-0">50-70</span>
                <span><strong>Medium:</strong> Logical conflicts or broad destination scopes to internal zones.</span>
              </li>
              <li className="flex gap-2">
                <span className="text-blue-500 font-bold w-12 shrink-0">&lt; 40</span>
                <span><strong>Low/Info:</strong> Policy hygiene issues, shadowed rules, or technical debt.</span>
              </li>
            </ul>
          </div>
        </section>

        <section className="bg-slate-900/50 border border-slate-800 p-6 rounded-2xl space-y-4">
          <h3 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-indigo-400" /> Core Security Logic
          </h3>
          <div className="space-y-4">
            <DocItem 
              title="Least Privilege" 
              desc="Restricting access to only what is necessary. We flag rules that have 'ANY' service or ports when they could be narrowed down to specific apps."
            />
            <DocItem 
              title="Zero Trust Baseline" 
              desc="Assuming no user or device is trusted by default. Any rule that bridges trust zones without strict identity/port control is flagged."
            />
            <DocItem 
              title="Network Segmentation" 
              desc="Dividing the network into small enclaves. We identify rules that allow communication across too many hosts (large CIDRs)."
            />
          </div>
        </section>
      </div>

      <section className="space-y-6">
        <h3 className="text-2xl font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-4">
          <Layers className="w-6 h-6 text-indigo-400" /> Understanding Policy Hygiene
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <HygieneDetail 
            title="Shadowed Rules"
            desc="Occurs when a rule is never hit because a broader rule above it matches the traffic first. It's 'dead code' in your firewall."
            impact="Increases latency, complicates audits, and leads to accidental over-permission."
          />
          <HygieneDetail 
            title="Logic Conflicts"
            desc="Multiple rules covering the same traffic with different actions (Allow/Deny). Creates non-deterministic behavior."
            impact="Causes 'Security Leakage' and inconsistent traffic handling."
          />
          <HygieneDetail 
            title="Latent Risk"
            desc="High-risk rules that are currently disabled. Adversaries can re-enable these if they gain control of management planes."
            impact="Provides a 'Quick Access' template for lateral movement after compromise."
          />
        </div>
      </section>

      <section className="bg-indigo-900/10 border border-indigo-500/20 p-8 rounded-3xl space-y-6">
        <div className="flex items-center gap-3">
          <Activity className="w-8 h-8 text-indigo-400" />
          <h3 className="text-2xl font-black text-white">Framework Compliance</h3>
        </div>
        <p className="text-indigo-200/80 max-w-3xl">
          RuleGuardX logic is derived from multiple industry standards. Every finding generated by the engine references technical controls 
          from the following organizations:
        </p>
        <div className="flex flex-wrap gap-4">
          <Badge label="NIST SP 800-41" />
          <Badge label="MITRE ATT&CK" />
          <Badge label="CIS Control 12" />
          <Badge label="PCI DSS 4.0" />
          <Badge label="SOC2 Type II" />
        </div>
      </section>
    </div>
  );
};

const DocItem = ({ title, desc }: { title: string, desc: string }) => (
  <div className="space-y-1">
    <h4 className="text-sm font-bold text-white uppercase tracking-wider">{title}</h4>
    <p className="text-xs text-slate-400 leading-relaxed">{desc}</p>
  </div>
);

const HygieneDetail = ({ title, desc, impact }: { title: string, desc: string, impact: string }) => (
  <div className="bg-slate-950 p-6 rounded-xl border border-slate-800 space-y-3">
    <h4 className="font-bold text-indigo-400">{title}</h4>
    <p className="text-sm text-slate-300 leading-relaxed">{desc}</p>
    <div className="pt-3 border-t border-slate-800">
      <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Impact</p>
      <p className="text-xs text-slate-400 italic">{impact}</p>
    </div>
  </div>
);

const Badge = ({ label }: { label: string }) => (
  <div className="px-3 py-1 bg-indigo-500/20 border border-indigo-500/40 rounded-full text-indigo-300 text-[10px] font-black uppercase tracking-widest">
    {label}
  </div>
);

export default DocumentationTab;