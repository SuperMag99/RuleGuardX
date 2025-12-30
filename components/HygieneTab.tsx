
import React from 'react';
import { AnalysisFinding } from '../types';
import { Layers, AlertTriangle, ShieldX, Info, HelpCircle } from 'lucide-react';

interface HygieneTabProps {
  hygiene: AnalysisFinding[];
}

const HYGIENE_DEFINITIONS = {
  'Shadowed Rules': 'A redundancy issue where a rule is placed after another more general rule that already handles all its traffic. The "shadowed" rule is never executed, creating unnecessary technical debt.',
  'Logic Conflicts': 'Ambiguity in policy enforcement where multiple rules overlap in criteria (source, destination, port) but specify different actions (Allow vs Deny). Device behavior becomes non-deterministic.',
  'Latent Risk': 'Security exposure that is present but currently inactive, such as high-risk rules that are disabled. These represent a primary target for "Defense Evasion" techniques.',
  'Policy Hygiene': 'Maintenance issues that don\'t break security but make the configuration harder to manage, such as redundant or empty rule definitions.',
  'Correlation Error': 'Critical logical overlapping where the firewall cannot reliably determine which action to take, potentially leading to unauthorized "Allow" leaks.'
};

const HygieneTab: React.FC<HygieneTabProps> = ({ hygiene }) => {
  return (
    <div className="space-y-6">
      <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 relative overflow-hidden">
        <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
          <Layers className="w-24 h-24" />
        </div>
        <h2 className="text-xl font-bold mb-2 flex items-center gap-2 relative z-10">
          <Layers className="w-6 h-6 text-indigo-400" /> Policy Correlation Analysis
        </h2>
        <p className="text-slate-400 text-sm relative z-10">Identifying shadowed, redundant, and conflicting firewall logic within the uploaded rule set.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <HygieneSummary 
           title="Shadowed Rules" 
           count={hygiene.filter(h => h.explanation.includes('Shadowed')).length}
           icon={Layers}
           color="text-yellow-500"
           description={HYGIENE_DEFINITIONS['Shadowed Rules']}
        />
        <HygieneSummary 
           title="Logic Conflicts" 
           count={hygiene.filter(h => h.category === 'Correlation Error').length}
           icon={ShieldX}
           color="text-red-500"
           description={HYGIENE_DEFINITIONS['Logic Conflicts']}
        />
        <HygieneSummary 
           title="Latent Risk" 
           count={hygiene.filter(h => h.explanation.includes('Disabled')).length}
           icon={AlertTriangle}
           color="text-orange-500"
           description={HYGIENE_DEFINITIONS['Latent Risk']}
        />
      </div>

      <div className="space-y-4">
        {hygiene.length > 0 ? hygiene.map((h, i) => (
          <div key={i} className="bg-slate-900 border border-slate-800 p-5 rounded-xl flex items-center gap-4 hover:border-slate-700 transition-colors group">
            <div className={`p-3 rounded-lg bg-slate-800 ${h.category === 'Correlation Error' ? 'text-red-400' : 'text-slate-400'}`}>
               <AlertTriangle className="w-6 h-6" />
            </div>
            <div className="flex-1">
               <div className="flex items-center gap-3 mb-1">
                 <div className="relative group/label">
                    <span className="text-[10px] font-black uppercase tracking-widest bg-slate-800 px-2 py-0.5 rounded border border-slate-700 cursor-help flex items-center gap-1 hover:text-indigo-400 transition-colors">
                      {h.category} <HelpCircle className="w-3 h-3 opacity-40" />
                    </span>
                    {/* Inline Badge Tooltip */}
                    <div className="absolute bottom-full left-0 mb-2 w-48 bg-slate-950 border border-slate-800 p-2 rounded shadow-2xl opacity-0 translate-y-1 pointer-events-none group-hover/label:opacity-100 group-hover/label:translate-y-0 transition-all z-30">
                       <p className="text-[9px] text-slate-300 font-medium leading-relaxed">
                          {HYGIENE_DEFINITIONS[h.category as keyof typeof HYGIENE_DEFINITIONS] || 'General policy maintenance finding.'}
                       </p>
                    </div>
                 </div>
                 <span className="text-sm font-bold text-slate-100">{h.ruleName}</span>
                 <span className="text-xs font-mono text-slate-500">ID: {h.ruleId}</span>
               </div>
               <p className="text-sm text-slate-400 leading-relaxed">{h.explanation}</p>
            </div>
            <div className="max-w-[250px] bg-slate-950/50 p-3 rounded-lg border border-slate-800 shadow-inner">
               <div className="flex items-center gap-1.5 mb-1.5">
                 <HelpCircle className="w-3 h-3 text-indigo-400" />
                 <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Remediation Action</p>
               </div>
               <p className="text-xs text-slate-300 italic leading-relaxed">{h.recommendation}</p>
            </div>
          </div>
        )) : (
          <div className="p-20 text-center text-slate-600 bg-slate-900/10 border-2 border-dashed border-slate-800 rounded-2xl">
            <Layers className="w-12 h-12 mx-auto mb-4 opacity-10" />
            <p className="text-lg">No hygiene issues detected. This policy shows clean correlation.</p>
          </div>
        )}
      </div>
    </div>
  );
};

const HygieneSummary = ({ title, count, icon: Icon, color, description }: { title: string, count: number, icon: any, color: string, description: string }) => (
  <div className="group/card relative">
    <div className="bg-slate-900/50 p-6 rounded-xl border border-slate-800 hover:border-indigo-500/50 transition-all shadow-lg cursor-help h-full">
      <div className="flex justify-between items-center mb-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold text-slate-500 uppercase tracking-widest">{title}</span>
          <Info className="w-3 h-3 text-slate-600 group-hover/card:text-indigo-400 transition-colors" />
        </div>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <span className="text-4xl font-black text-white">{count}</span>
    </div>

    {/* Floating Description */}
    <div className="absolute top-full left-0 mt-3 w-full bg-slate-950 border border-slate-800 p-4 rounded-xl shadow-2xl opacity-0 translate-y-2 pointer-events-none group-hover/card:opacity-100 group-hover/card:translate-y-0 transition-all z-20 border-t-indigo-500 border-t-2">
      <div className="flex items-start gap-3">
        <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
        <p className="text-xs text-slate-300 leading-relaxed font-medium">
          <span className="text-white font-bold block mb-1">Concept: {title}</span>
          {description}
        </p>
      </div>
    </div>
  </div>
);

export default HygieneTab;
