
import React, { useState } from 'react';
import { FirewallRule, AnalysisFinding, Severity, FilterState, FilterClause } from '../types';
import { Shield, ShieldAlert, ShieldCheck, ArrowRight, ChevronDown, ChevronUp, AlertCircle, Info, Filter as FilterIcon } from 'lucide-react';
import { SEVERITY_COLORS } from '../constants';

interface RuleTableProps {
  rules: FirewallRule[];
  findings: AnalysisFinding[];
  filters: FilterState;
}

const RuleTable: React.FC<RuleTableProps> = ({ rules, findings, filters }) => {
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  const ruleToFindings = React.useMemo(() => {
    const map: Record<string, AnalysisFinding[]> = {};
    findings.forEach(f => {
      if (!map[f.ruleId]) map[f.ruleId] = [];
      map[f.ruleId].push(f);
    });
    return map;
  }, [findings]);

  const ruleRisks = React.useMemo(() => {
    const riskMap: Record<string, { severity: Severity; count: number }> = {};
    Object.entries(ruleToFindings).forEach(([id, ruleFindings]) => {
      let highest: Severity = 'INFORMATIONAL';
      const severities: Severity[] = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const findingsArray = ruleFindings as AnalysisFinding[];
      findingsArray.forEach(f => {
        const currentIdx = severities.indexOf(highest);
        const newIdx = severities.indexOf(f.severity);
        if (newIdx > currentIdx) highest = f.severity;
      });
      riskMap[id] = { severity: highest, count: findingsArray.length };
    });
    return riskMap;
  }, [ruleToFindings]);

  const evaluateClause = (rule: FirewallRule, clause: FilterClause, findings: AnalysisFinding[], risk?: { severity: Severity }): boolean => {
    let targetValue: string = '';
    
    // Field Mapping
    if (clause.field === 'severity') targetValue = risk?.severity || 'INFORMATIONAL';
    else if (clause.field === 'category') targetValue = findings.map(f => f.category).join(' ');
    else targetValue = String((rule as any)[clause.field] || '').toLowerCase();

    const val = clause.value.toLowerCase();
    const tVal = targetValue.toLowerCase();

    // Port handling (numerical)
    if (clause.field === 'destinationPort') {
      const numericTarget = parseInt(targetValue.split(/[,-]/)[0].replace(/[^\d]/g, ''), 10);
      const numericVal = parseInt(val, 10);
      
      if (!isNaN(numericTarget) && !isNaN(numericVal)) {
        if (clause.operator === 'GREATER_THAN') return numericTarget > numericVal;
        if (clause.operator === 'LESS_THAN') return numericTarget < numericVal;
      }
    }

    switch (clause.operator) {
      case 'CONTAINS': return tVal.includes(val);
      case 'NOT_CONTAINS': return !tVal.includes(val);
      case 'EQUALS': return tVal === val;
      case 'NOT_EQUALS': return tVal !== val;
      case 'STARTS_WITH': return tVal.startsWith(val);
      case 'ENDS_WITH': return tVal.endsWith(val);
      case 'GREATER_THAN': return targetValue > clause.value;
      case 'LESS_THAN': return targetValue < clause.value;
      default: return true;
    }
  };

  const filteredRules = React.useMemo(() => {
    return rules.filter(rule => {
      const risk = ruleRisks[rule.id];
      const ruleFindings = ruleToFindings[rule.id] || [];

      // Global Quick Search
      const quickSearchMatch = !filters.quickSearch || [
        rule.name, rule.id, rule.source, rule.destination, rule.destinationPort, rule.description
      ].some(field => String(field).toLowerCase().includes(filters.quickSearch.toLowerCase()));

      if (!quickSearchMatch) return false;

      // Clauses Evaluation
      if (filters.clauses.length === 0) return true;

      let result = evaluateClause(rule, filters.clauses[0], ruleFindings, risk);

      for (let i = 1; i < filters.clauses.length; i++) {
        const clause = filters.clauses[i];
        const clauseResult = evaluateClause(rule, clause, ruleFindings, risk);
        
        if (clause.logicalOperator === 'AND') {
          result = result && clauseResult;
        } else {
          result = result || clauseResult;
        }
      }

      return result;
    });
  }, [rules, filters, ruleRisks, ruleToFindings]);

  const toggleExpand = (id: string) => {
    setExpandedRuleId(expandedRuleId === id ? null : id);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-lg font-bold text-white">Rule Repository</h3>
          <span className="bg-slate-800 px-2 py-0.5 rounded text-[10px] font-mono text-slate-400">
            {filteredRules.length} matches
          </span>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-950 text-slate-400 text-[10px] font-black uppercase tracking-widest">
                <th className="px-4 py-4 border-b border-slate-800 w-10"></th>
                <th className="px-6 py-4 border-b border-slate-800">Risk Assessment</th>
                <th className="px-6 py-4 border-b border-slate-800">Config Status</th>
                <th className="px-6 py-4 border-b border-slate-800">ID / Name</th>
                <th className="px-6 py-4 border-b border-slate-800">Action</th>
                <th className="px-6 py-4 border-b border-slate-800">Source</th>
                <th className="px-6 py-4 border-b border-slate-800">Destination</th>
                <th className="px-6 py-4 border-b border-slate-800">Service/Port</th>
                <th className="px-6 py-4 border-b border-slate-800">Protocol</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredRules.length > 0 ? filteredRules.map((rule) => {
                const ruleFindings = ruleToFindings[rule.id] || [];
                const risk = ruleRisks[rule.id];
                const isExpanded = expandedRuleId === rule.id;
                const isInsecure = rule.enabled && rule.action === 'ALLOW' && risk;
                
                let rowClass = "";
                if (isInsecure) {
                  if (risk.severity === 'CRITICAL') rowClass = "bg-red-500/5 hover:bg-red-500/10";
                  else if (risk.severity === 'HIGH') rowClass = "bg-orange-500/5 hover:bg-orange-500/10";
                  else rowClass = "bg-yellow-500/5 hover:bg-yellow-500/10";
                } else if (!rule.enabled) {
                  rowClass = "opacity-40 bg-slate-950/30";
                } else {
                  rowClass = "hover:bg-slate-800/50";
                }

                return (
                  <React.Fragment key={rule.id}>
                    <tr 
                      className={`${rowClass} transition-colors group cursor-pointer`}
                      onClick={() => toggleExpand(rule.id)}
                    >
                      <td className="px-4 py-4 text-center">
                        {ruleFindings.length > 0 && (
                          isExpanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />
                        )}
                      </td>
                      <td className="px-6 py-4">
                        {isInsecure ? (
                          <div className="flex items-center gap-3">
                            <div className={`p-1.5 rounded-full ${
                              risk.severity === 'CRITICAL' ? 'bg-red-500/20' : 
                              risk.severity === 'HIGH' ? 'bg-orange-500/20' : 'bg-yellow-500/20'
                            }`}>
                              <ShieldAlert className={`w-4 h-4 ${
                                risk.severity === 'CRITICAL' ? 'text-red-500' : 
                                risk.severity === 'HIGH' ? 'text-orange-500' : 'text-yellow-500'
                              }`} />
                            </div>
                            <div className="flex flex-col">
                               <span className={`text-[9px] font-black uppercase tracking-tight ${
                                 risk.severity === 'CRITICAL' ? 'text-red-400' : 
                                 risk.severity === 'HIGH' ? 'text-orange-400' : 'text-yellow-400'
                               }`}>
                                 Insecure ({risk.severity})
                               </span>
                               <span className="text-[8px] text-slate-500">{risk.count} findings</span>
                            </div>
                          </div>
                        ) : rule.action === 'DENY' || !rule.enabled ? (
                          <div className="flex items-center gap-3 text-slate-600">
                            <Shield className="w-4 h-4 opacity-30" />
                            <span className="text-[9px] font-bold uppercase">Passive</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-3 text-green-500">
                            <div className="p-1.5 rounded-full bg-green-500/10">
                               <ShieldCheck className="w-4 h-4" />
                            </div>
                            <span className="text-[9px] font-black uppercase">Secure</span>
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        {rule.enabled ? (
                          <span className="text-[10px] font-bold text-green-500 uppercase bg-green-500/10 px-2 py-0.5 rounded">Enabled</span>
                        ) : (
                          <span className="text-[10px] font-bold text-slate-500 uppercase bg-slate-800 px-2 py-0.5 rounded">Disabled</span>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-col">
                          <span className="text-sm font-bold text-slate-100">{rule.name}</span>
                          <span className="text-[10px] font-mono text-slate-500">ID: {rule.id}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`text-[10px] font-black px-2 py-0.5 rounded border ${
                          rule.action === 'ALLOW' 
                            ? 'text-green-400 border-green-400/30 bg-green-400/5' 
                            : 'text-red-400 border-red-400/30 bg-red-400/5'
                        }`}>
                          {rule.action}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-xs font-mono text-slate-400">{rule.source}</td>
                      <td className="px-6 py-4">
                         <div className="flex items-center gap-2">
                           <ArrowRight className="w-3 h-3 text-slate-600" />
                           <span className="text-xs font-mono text-slate-400">{rule.destination}</span>
                         </div>
                      </td>
                      <td className="px-6 py-4">
                         <div className="flex flex-col">
                           <span className="text-xs font-bold text-slate-300">{rule.destinationPort}</span>
                           {rule.service && <span className="text-[10px] text-slate-500 truncate max-w-[120px]">{rule.service}</span>}
                         </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-[10px] font-bold text-slate-500 bg-slate-800 px-1.5 py-0.5 rounded">
                          {rule.protocol}
                        </span>
                      </td>
                    </tr>
                    
                    {isExpanded && ruleFindings.length > 0 && (
                      <tr className="bg-slate-950/80 border-l-4 border-indigo-500">
                        <td colSpan={9} className="px-10 py-6">
                          <div className="space-y-4">
                            <h5 className="text-xs font-black uppercase tracking-[0.2em] text-indigo-400 flex items-center gap-2">
                               <AlertCircle className="w-4 h-4" /> Security Analysis Findings
                            </h5>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              {ruleFindings.map((finding, fIdx) => (
                                <div key={fIdx} className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-2">
                                  <div className="flex items-center justify-between">
                                    <span className={`text-[9px] font-black px-2 py-0.5 rounded ${SEVERITY_COLORS[finding.severity]}`}>
                                      {finding.severity}
                                    </span>
                                    <span className="text-[10px] font-bold text-slate-500 uppercase">{finding.category}</span>
                                  </div>
                                  <p className="text-sm text-slate-200 leading-relaxed font-medium">
                                    {finding.explanation}
                                  </p>
                                  <div className="pt-2 border-t border-slate-800 mt-2">
                                    <div className="flex items-start gap-2">
                                      <Info className="w-3 h-3 text-indigo-400 mt-0.5 shrink-0" />
                                      <p className="text-[11px] text-slate-400 italic">
                                        <span className="font-bold text-indigo-400 not-italic uppercase tracking-tighter mr-1">Remediation:</span>
                                        {finding.recommendation}
                                      </p>
                                    </div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              }) : (
                <tr>
                  <td colSpan={9} className="py-20 text-center text-slate-600 italic">
                    <FilterIcon className="w-12 h-12 mx-auto mb-4 opacity-10" />
                    No rules found matching the current filter profile.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default RuleTable;
