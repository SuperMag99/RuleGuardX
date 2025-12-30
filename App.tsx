import React, { useState, useCallback, useMemo, useEffect } from 'react';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import Uploader from './components/Uploader';
import FindingsList from './components/FindingsList';
import RuleTable from './components/RuleTable';
import Settings from './components/Settings';
import HygieneTab from './components/HygieneTab';
import FilterBar from './components/FilterBar';
import DocumentationTab from './components/DocumentationTab';
import { analyzeRules } from './engine/analyzer';
import { FirewallRule, AnalysisResults, InsecurePortSetting, FilterState, FilterClause } from './types';
import { DEFAULT_INSECURE_PORTS } from './constants';
import { ShieldAlert, FileCheck, Search, Database } from 'lucide-react';

const STORAGE_KEY = 'ruleguardx_port_settings';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState('import');
  const [rawRules, setRawRules] = useState<FirewallRule[]>([]);
  const [filters, setFilters] = useState<FilterState>({
    clauses: [],
    quickSearch: ''
  });
  
  // Initialize port settings from localStorage or fallback to defaults
  const [portSettings, setPortSettings] = useState<InsecurePortSetting[]>(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error("Failed to parse saved settings", e);
      }
    }
    return DEFAULT_INSECURE_PORTS;
  });

  const results = useMemo(() => {
    if (rawRules.length === 0) return null;
    return analyzeRules(rawRules, portSettings);
  }, [rawRules, portSettings]);

  const handleDataLoaded = (rules: FirewallRule[]) => {
    setRawRules(rules);
    setActiveTab('dashboard');
  };

  const handleSettingsSave = (newSettings: InsecurePortSetting[]) => {
    setPortSettings(newSettings);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(newSettings));
    if (rawRules.length > 0) {
      setActiveTab('dashboard');
    }
  };

  const navigateWithFilters = (tab: string, clauses: FilterClause[]) => {
    setFilters({
      quickSearch: '',
      clauses: clauses
    });
    setActiveTab(tab);
  };

  const categories = useMemo(() => {
    if (!results) return [];
    const cats = new Set<string>();
    results.findings.forEach(f => cats.add(f.category));
    return Array.from(cats);
  }, [results]);

  const renderContent = () => {
    if (activeTab === 'import') {
      return (
        <div className="space-y-12 py-10 animate-in slide-in-from-bottom duration-500">
          <div className="text-center space-y-4 max-w-2xl mx-auto">
             <div className="inline-flex items-center gap-2 px-3 py-1 bg-indigo-500/10 border border-indigo-500/20 rounded-full text-indigo-400 text-xs font-bold uppercase tracking-widest">
               <FileCheck className="w-3 h-3" /> Firewall Rules Auditor
             </div>
             <h2 className="text-5xl font-black text-white tracking-tight leading-tight">RuleGuard<span className="text-indigo-500">X</span></h2>
             <p className="text-slate-400 text-lg leading-relaxed">
               Fully offline firewall rule analyzer. Map ports, subnets, and rule correlation to find true risk without false positives.
             </p>
          </div>
          <Uploader onDataLoaded={handleDataLoaded} />
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-5xl mx-auto mt-20">
             <FeatureCard 
               icon={ShieldAlert} 
               title="Strict Port Matrix" 
               description="35+ high-risk services evaluated by default. Fully customizable."
             />
             <FeatureCard 
               icon={Search} 
               title="The 'ANY' Rule" 
               description="Any/Any rules are automatically flagged as Critical risk factors."
             />
             <FeatureCard 
               icon={Database} 
               title="Correlation Engine" 
               description="Detect shadowed, conflicting, and over-permissive rule subsets."
             />
          </div>
        </div>
      );
    }

    if (activeTab === 'settings') {
      return <Settings settings={portSettings} onSave={handleSettingsSave} />;
    }

    if (activeTab === 'docs') {
      return <DocumentationTab />;
    }

    if (!results) return null;

    return (
      <div className="space-y-6">
        {activeTab !== 'dashboard' && activeTab !== 'hygiene' && activeTab !== 'docs' && (
          <FilterBar filters={filters} setFilters={setFilters} categories={categories} />
        )}
        
        {(() => {
          switch (activeTab) {
            case 'dashboard':
              return <Dashboard results={results} onNavigate={navigateWithFilters} />;
            case 'findings':
              return <FindingsList findings={results.findings} rules={results.rules} filters={filters} />;
            case 'hygiene':
              return <HygieneTab hygiene={results.hygiene} />;
            case 'rules':
              return <RuleTable rules={results.rules} findings={results.findings} filters={filters} />;
            default:
              return <Dashboard results={results} onNavigate={navigateWithFilters} />;
          }
        })()}
      </div>
    );
  };

  return (
    <Layout 
      activeTab={activeTab} 
      setActiveTab={setActiveTab} 
      isAnalyzed={rawRules.length > 0}
    >
      {renderContent()}
    </Layout>
  );
};

const FeatureCard: React.FC<{ icon: any, title: string, description: string }> = ({ icon: Icon, title, description }) => (
  <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl hover:bg-slate-900 transition-all hover:border-indigo-500/30 group">
    <div className="bg-slate-800 w-12 h-12 flex items-center justify-center rounded-xl mb-4 group-hover:scale-110 transition-transform">
      <Icon className="w-6 h-6 text-indigo-400" />
    </div>
    <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
    <p className="text-sm text-slate-500 leading-relaxed">{description}</p>
  </div>
);

export default App;