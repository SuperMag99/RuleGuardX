
import React from 'react';
import { FilterState, FilterClause, FilterField, FilterOperator } from '../types';
import { Search, Plus, Trash2, Filter, Settings2, HelpCircle } from 'lucide-react';

interface FilterBarProps {
  filters: FilterState;
  setFilters: React.Dispatch<React.SetStateAction<FilterState>>;
  categories: string[];
}

const FIELDS: { value: FilterField; label: string }[] = [
  { value: 'id', label: 'Rule ID' },
  { value: 'name', label: 'Rule Name' },
  { value: 'source', label: 'Source IP/Net' },
  { value: 'destination', label: 'Dest IP/Net' },
  { value: 'destinationPort', label: 'Port' },
  { value: 'protocol', label: 'Protocol' },
  { value: 'action', label: 'Action' },
  { value: 'severity', label: 'Risk Severity' },
  { value: 'category', label: 'Risk Category' },
  { value: 'description', label: 'Description' },
];

const OPERATORS: { value: FilterOperator; label: string }[] = [
  { value: 'CONTAINS', label: 'Contains' },
  { value: 'NOT_CONTAINS', label: 'Does Not Contain' },
  { value: 'EQUALS', label: 'Equals' },
  { value: 'NOT_EQUALS', label: 'Does Not Equal' },
  { value: 'STARTS_WITH', label: 'Starts With' },
  { value: 'ENDS_WITH', label: 'Ends With' },
  { value: 'GREATER_THAN', label: 'Greater Than' },
  { value: 'LESS_THAN', label: 'Less Than' },
];

const FilterBar: React.FC<FilterBarProps> = ({ filters, setFilters, categories }) => {
  const addClause = () => {
    const newClause: FilterClause = {
      id: Math.random().toString(36).substr(2, 9),
      field: 'name',
      operator: 'CONTAINS',
      value: '',
      logicalOperator: 'AND',
    };
    setFilters(prev => ({ ...prev, clauses: [...prev.clauses, newClause] }));
  };

  const removeClause = (id: string) => {
    setFilters(prev => ({ ...prev, clauses: prev.clauses.filter(c => c.id !== id) }));
  };

  const updateClause = (id: string, updates: Partial<FilterClause>) => {
    setFilters(prev => ({
      ...prev,
      clauses: prev.clauses.map(c => (c.id === id ? { ...c, ...updates } : c)),
    }));
  };

  const updateQuickSearch = (val: string) => {
    setFilters(prev => ({ ...prev, quickSearch: val }));
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6 shadow-2xl relative overflow-hidden group">
      <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
        <Filter className="w-24 h-24" />
      </div>

      <div className="flex flex-col gap-6 relative z-10">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Settings2 className="w-5 h-5 text-indigo-400" />
            <h3 className="text-sm font-black uppercase tracking-widest text-white">Advanced Policy Filter</h3>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setFilters({ clauses: [], quickSearch: '' })}
              className="text-[10px] font-bold text-slate-500 hover:text-white uppercase px-2 py-1 rounded hover:bg-slate-800 transition-all"
            >
              Clear All
            </button>
          </div>
        </div>

        {/* Clauses List */}
        <div className="space-y-4">
          {filters.clauses.map((clause, index) => (
            <div key={clause.id} className="flex flex-col gap-2 animate-in slide-in-from-left-2 duration-300">
              {index > 0 && (
                <div className="flex items-center gap-2 ml-4">
                  <div className="w-8 h-[1px] bg-slate-800" />
                  <div className="flex bg-slate-950 rounded-lg p-0.5 border border-slate-800">
                    <button
                      onClick={() => updateClause(clause.id, { logicalOperator: 'AND' })}
                      className={`px-3 py-1 text-[9px] font-black uppercase rounded transition-all ${clause.logicalOperator === 'AND' ? 'bg-indigo-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
                    >
                      AND
                    </button>
                    <button
                      onClick={() => updateClause(clause.id, { logicalOperator: 'OR' })}
                      className={`px-3 py-1 text-[9px] font-black uppercase rounded transition-all ${clause.logicalOperator === 'OR' ? 'bg-orange-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
                    >
                      OR
                    </button>
                  </div>
                  <div className="flex-1 h-[1px] bg-slate-800" />
                </div>
              )}
              
              <div className="flex flex-wrap items-center gap-3 bg-slate-950/30 p-2 rounded-xl border border-transparent hover:border-slate-800/50 transition-all shadow-inner">
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-1 flex items-center shadow-inner">
                  <select 
                    value={clause.field}
                    onChange={e => updateClause(clause.id, { field: e.target.value as FilterField })}
                    className="bg-transparent text-xs font-bold text-slate-300 px-2 outline-none cursor-pointer"
                  >
                    {FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
                  </select>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-1 flex items-center shadow-inner">
                  <select 
                    value={clause.operator}
                    onChange={e => updateClause(clause.id, { operator: e.target.value as FilterOperator })}
                    className="bg-transparent text-xs font-bold text-indigo-400 px-2 outline-none cursor-pointer"
                  >
                    {OPERATORS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>

                <div className="flex-1 min-w-[200px] relative">
                  <input 
                    type="text"
                    placeholder="Filter value..."
                    value={clause.value}
                    onChange={e => updateClause(clause.id, { value: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 outline-none transition-all"
                  />
                </div>

                <button 
                  onClick={() => removeClause(clause.id)}
                  className="p-2 text-slate-600 hover:text-red-500 transition-colors"
                  title="Remove Filter"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}

          <button 
            onClick={addClause}
            className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-indigo-400 hover:text-indigo-300 py-2 group/add"
          >
            <div className="p-1 rounded bg-indigo-500/10 border border-indigo-500/20 group-hover/add:bg-indigo-500/20 transition-all">
              <Plus className="w-3 h-3" />
            </div>
            Add Filter Clause
          </button>
        </div>

        {/* Search & Meta */}
        <div className="pt-4 border-t border-slate-800/50 flex flex-col md:flex-row items-center gap-6">
          <div className="flex-1 relative w-full">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input 
              type="text"
              placeholder="Quick global search (all fields)..."
              value={filters.quickSearch}
              onChange={e => updateQuickSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-3 text-xs text-white focus:border-indigo-500 outline-none shadow-inner transition-all"
            />
          </div>
          <div className="flex items-center gap-2 text-[10px] text-slate-500 font-bold uppercase shrink-0">
             <HelpCircle className="w-3 h-3 text-indigo-400/50" />
             Queries are evaluated linearly with logical operators.
          </div>
        </div>
      </div>
    </div>
  );
};

export default FilterBar;
