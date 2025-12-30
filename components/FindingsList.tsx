
import React from 'react';
import { AnalysisFinding, FilterState, FilterClause, FirewallRule } from '../types';
import { SEVERITY_COLORS } from '../constants';
import { AlertCircle, Download, Filter } from 'lucide-react';

interface FindingsListProps {
  findings: AnalysisFinding[];
  rules: FirewallRule[];
  filters: FilterState;
}

const FindingsList: React.FC<FindingsListProps> = ({ findings, rules, filters }) => {
  const evaluateClause = (f: AnalysisFinding, clause: FilterClause): boolean => {
    let targetValue: string = '';
    const associatedRule = rules.find(r => r.id === f.ruleId);
    
    // Universal Field Mapping for Findings (including Rule data join)
    if (clause.field === 'id') targetValue = f.ruleId;
    else if (clause.field === 'name') targetValue = f.ruleName;
    else if (clause.field === 'severity') targetValue = f.severity;
    else if (clause.field === 'category') targetValue = f.category;
    else if (clause.field === 'description') targetValue = f.explanation;
    else if (clause.field === 'source') targetValue = associatedRule?.source || '';
    else if (clause.field === 'destination') targetValue = associatedRule?.destination || '';
    else if (clause.field === 'destinationPort') targetValue = associatedRule?.destinationPort || '';
    else if (clause.field === 'protocol') targetValue = associatedRule?.protocol || '';
    else if (clause.field === 'action') targetValue = associatedRule?.action || '';
    else return true;

    const val = clause.value.toLowerCase();
    const tVal = targetValue.toLowerCase();

    // Numerical Port Handling
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

  const filtered = findings.filter(f => {
    const quickSearchMatch = !filters.quickSearch || [
      f.explanation, f.ruleName, f.ruleId, f.category, f.severity
    ].some(field => String(field).toLowerCase().includes(filters.quickSearch.toLowerCase()));

    if (!quickSearchMatch) return false;

    if (filters.clauses.length === 0) return true;

    let result = evaluateClause(f, filters.clauses[0]);

    for (let i = 1; i < filters.clauses.length; i++) {
      const clause = filters.clauses[i];
      const clauseResult = evaluateClause(f, clause);
      
      if (clause.logicalOperator === 'AND') {
        result = result && clauseResult;
      } else {
        result = result || clauseResult;
      }
    }
    
    return result;
  }).sort((a, b) => b.score - a.score);

  const downloadReport = () => {
    const data = JSON.stringify(findings, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'firewall_findings.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h3 className="text-lg font-bold text-white">Analysis Findings</h3>
          <span className="bg-slate-800 px-2 py-0.5 rounded text-[10px] font-mono text-slate-400">
            Showing {filtered.length} of {findings.length}
          </span>
        </div>
        <button 
          onClick={downloadReport}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all"
        >
          <Download className="w-4 h-4" /> Export Report
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {filtered.length > 0 ? filtered.map((finding, idx) => (
          <div 
            key={`${finding.ruleId}-${idx}`} 
            className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-all group"
          >
            <div className="flex items-stretch">
              <div className={`w-2 ${
                finding.severity === 'CRITICAL' ? 'bg-red-600' : 
                finding.severity === 'HIGH' ? 'bg-orange-500' : 
                finding.severity === 'MEDIUM' ? 'bg-yellow-500' : 
                finding.severity === 'LOW' ? 'bg-blue-500' : 'bg-slate-600'
              }`} />
              <div className="p-5 flex-1 space-y-3">
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-3">
                      <span className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded ${SEVERITY_COLORS[finding.severity]}`}>
                        {finding.severity}
                      </span>
                      <span className="text-xs font-mono text-slate-500">SCORE: {finding.score}</span>
                      <span className="text-xs font-bold text-indigo-400 uppercase tracking-tighter">{finding.category}</span>
                    </div>
                    <h4 className="text-lg font-bold group-hover:text-indigo-400 transition-colors">
                      {finding.ruleName} <span className="text-slate-600 font-mono text-sm ml-2">ID: {finding.ruleId}</span>
                    </h4>
                  </div>
                  <AlertCircle className={`w-5 h-5 ${finding.severity === 'CRITICAL' ? 'text-red-500' : 'text-slate-500'}`} />
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2 border-t border-slate-800/50">
                  <div className="space-y-2">
                    <p className="text-xs font-bold text-slate-500 uppercase tracking-widest">Finding Detail</p>
                    <p className="text-sm text-slate-300 leading-relaxed">{finding.explanation}</p>
                  </div>
                  <div className="space-y-2 bg-slate-950/50 p-3 rounded-lg border border-slate-800/50">
                    <p className="text-xs font-bold text-green-500 uppercase tracking-widest">Remediation Recommendation</p>
                    <p className="text-sm text-slate-400 italic leading-relaxed">{finding.recommendation}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )) : (
          <div className="flex flex-col items-center justify-center p-20 text-slate-600 bg-slate-900/20 border border-dashed border-slate-800 rounded-2xl">
            <Filter className="w-12 h-12 mb-4 opacity-20" />
            <p className="text-lg font-medium">No findings match your filters.</p>
            <p className="text-sm">Refine your search parameters to explore other risks.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default FindingsList;
