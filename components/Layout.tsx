
import React from 'react';
import { Shield, LayoutDashboard, FileWarning, Table, FileCode, Settings as SettingsIcon, Layers, BookOpen, Github, Linkedin } from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isAnalyzed: boolean;
}

const Layout: React.FC<LayoutProps> = ({ children, activeTab, setActiveTab, isAnalyzed }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, disabled: !isAnalyzed },
    { id: 'findings', label: 'Findings', icon: FileWarning, disabled: !isAnalyzed },
    { id: 'hygiene', label: 'Hygiene', icon: Layers, disabled: !isAnalyzed },
    { id: 'rules', label: 'Rules Data', icon: Table, disabled: !isAnalyzed },
    { id: 'docs', label: 'Documentation', icon: BookOpen, disabled: false },
    { id: 'settings', label: 'Settings', icon: SettingsIcon, disabled: false },
    { id: 'import', label: 'Import CSV', icon: FileCode, disabled: false },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-slate-900 border-b border-slate-800 px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="bg-indigo-600 p-2 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">RuleGuard<span className="text-indigo-500 text-2xl">X</span></h1>
            <p className="text-xs text-slate-400 font-medium uppercase tracking-widest">Firewall Rules Auditor</p>
          </div>
        </div>
        <nav className="flex items-center gap-1">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => !item.disabled && setActiveTab(item.id)}
              disabled={item.disabled}
              className={`flex items-center gap-2 px-4 py-3 rounded-md transition-all duration-200 ${
                activeTab === item.id 
                  ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/30' 
                  : item.disabled 
                    ? 'text-slate-600 cursor-not-allowed opacity-50' 
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <item.icon className="w-4 h-4" />
              <span className="text-sm font-medium">{item.label}</span>
            </button>
          ))}
        </nav>
      </header>
      <main className="flex-1 max-w-[1600px] mx-auto w-full p-6">
        {children}
      </main>
      <footer className="bg-slate-900 border-t border-slate-800 p-8 text-center space-y-4">
         <div className="flex items-center justify-center gap-6 mb-2">
           <a 
             href="https://github.com/SuperMag99" 
             target="_blank" 
             rel="noopener noreferrer"
             className="text-slate-500 hover:text-white transition-colors flex items-center gap-2 text-sm font-medium"
             title="Follow on GitHub"
           >
             <Github className="w-5 h-5" /> <span>SuperMag99</span>
           </a>
           <a 
             href="https://www.linkedin.com/in/mag99/" 
             target="_blank" 
             rel="noopener noreferrer"
             className="text-slate-500 hover:text-indigo-400 transition-colors flex items-center gap-2 text-sm font-medium"
             title="Connect on LinkedIn"
           >
             <Linkedin className="w-5 h-5" /> <span>mag99</span>
           </a>
         </div>
         <div className="space-y-1">
           <p className="text-slate-500 text-xs uppercase tracking-widest font-semibold flex items-center justify-center gap-2">
             <Shield className="w-3 h-3" /> RuleGuardX - Firewall Rules Auditor v2.0.0
           </p>
           <p className="text-slate-600 text-[10px] uppercase tracking-tighter">
             Copyright © 2025 RuleGuardX. Released under the MIT License.
           </p>
         </div>
      </footer>
    </div>
  );
};

export default Layout;
