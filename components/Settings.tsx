
import React, { useState, useEffect } from 'react';
import { InsecurePortSetting, Severity } from '../types';
import { Save, Plus, Trash2, CheckCircle2 } from 'lucide-react';

interface SettingsProps {
  settings: InsecurePortSetting[];
  onSave: (newSettings: InsecurePortSetting[]) => void;
}

const Settings: React.FC<SettingsProps> = ({ settings, onSave }) => {
  const [currentSettings, setCurrentSettings] = useState<InsecurePortSetting[]>(settings);
  const [newPort, setNewPort] = useState({ port: '', label: '', criticality: 'MEDIUM' as Severity });
  const [showSavedToast, setShowSavedToast] = useState(false);

  // Sync with prop if it changes externally
  useEffect(() => {
    setCurrentSettings(settings);
  }, [settings]);

  const togglePort = (port: number) => {
    setCurrentSettings(prev => prev.map(s => s.port === port ? { ...s, enabled: !s.enabled } : s));
  };

  const addCustomPort = () => {
    const p = parseInt(newPort.port);
    if (isNaN(p) || !newPort.label) return;
    
    // Check if port already exists
    if (currentSettings.some(s => s.port === p)) {
      alert(`Port ${p} is already in the check list.`);
      return;
    }

    const newItem: InsecurePortSetting = {
      port: p,
      label: newPort.label,
      criticality: newPort.criticality,
      whyInsecure: 'User-defined custom risk',
      enabled: true
    };
    setCurrentSettings([...currentSettings, newItem]);
    setNewPort({ port: '', label: '', criticality: 'MEDIUM' });
  };

  const removePort = (port: number) => {
    setCurrentSettings(prev => prev.filter(s => s.port !== port));
  };

  const handleApply = () => {
    onSave(currentSettings);
    setShowSavedToast(true);
    setTimeout(() => setShowSavedToast(false), 3000);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-2xl font-bold">Audit Engine Settings</h2>
          <p className="text-slate-400 text-sm">Configure which ports and protocols are flagged as insecure.</p>
        </div>
        <div className="flex items-center gap-4">
          {showSavedToast && (
            <span className="text-green-500 text-xs font-black uppercase tracking-widest animate-pulse">Configuration Applied</span>
          )}
          <button 
            onClick={handleApply}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 px-6 py-2 rounded-lg font-bold transition-all shadow-lg shadow-indigo-500/20 active:scale-95"
          >
            <Save className="w-4 h-4" /> Apply Configuration
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col max-h-[700px]">
          <div className="overflow-y-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950 text-slate-500 uppercase text-[10px] font-black tracking-widest sticky top-0 z-10">
                <tr>
                  <th className="px-6 py-4">Flag</th>
                  <th className="px-6 py-4">Port</th>
                  <th className="px-6 py-4">Service</th>
                  <th className="px-6 py-4">Risk</th>
                  <th className="px-6 py-4">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {currentSettings.map((s) => (
                  <tr key={s.port} className={`hover:bg-slate-800/30 transition-colors ${!s.enabled && 'opacity-40'}`}>
                    <td className="px-6 py-4">
                      <input 
                        type="checkbox" 
                        checked={s.enabled} 
                        onChange={() => togglePort(s.port)}
                        className="w-4 h-4 accent-indigo-500 bg-slate-800 border-slate-700 rounded cursor-pointer"
                      />
                    </td>
                    <td className="px-6 py-4 font-mono font-bold text-slate-300">{s.port}</td>
                    <td className="px-6 py-4">{s.label}</td>
                    <td className="px-6 py-4">
                      <span className={`text-[10px] font-black px-2 py-0.5 rounded ${s.criticality === 'HIGH' ? 'text-red-400' : s.criticality === 'MEDIUM' ? 'text-yellow-400' : 'text-blue-400'}`}>
                        {s.criticality}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button onClick={() => removePort(s.port)} className="text-slate-600 hover:text-red-400 p-1 rounded hover:bg-red-400/10">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 space-y-4 shadow-xl">
            <h3 className="font-bold flex items-center gap-2">
              <Plus className="w-4 h-4 text-indigo-400" /> Add Custom Check
            </h3>
            <div className="space-y-4">
              <div>
                <label className="text-xs font-bold text-slate-500 block mb-1">PORT NUMBER</label>
                <input 
                  type="text" 
                  value={newPort.port} 
                  onChange={e => setNewPort({...newPort, port: e.target.value.replace(/\D/g, '')})}
                  className="w-full bg-slate-800 border border-slate-700 rounded-md px-3 py-2 text-sm focus:ring-1 focus:ring-indigo-500 outline-none text-white"
                  placeholder="e.g. 5000"
                />
              </div>
              <div>
                <label className="text-xs font-bold text-slate-500 block mb-1">LABEL / PROTOCOL</label>
                <input 
                  type="text" 
                  value={newPort.label} 
                  onChange={e => setNewPort({...newPort, label: e.target.value})}
                  className="w-full bg-slate-800 border border-slate-700 rounded-md px-3 py-2 text-sm focus:ring-1 focus:ring-indigo-500 outline-none text-white"
                  placeholder="e.g. Custom Web"
                />
              </div>
              <div>
                <label className="text-xs font-bold text-slate-500 block mb-1">CRITICALITY</label>
                <select 
                  value={newPort.criticality} 
                  onChange={e => setNewPort({...newPort, criticality: e.target.value as Severity})}
                  className="w-full bg-slate-800 border border-slate-700 rounded-md px-3 py-2 text-sm focus:ring-1 focus:ring-indigo-500 outline-none text-white"
                >
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
              <button 
                onClick={addCustomPort}
                className="w-full bg-indigo-600/10 hover:bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 font-bold py-2 rounded-md transition-colors"
              >
                Add to List
              </button>
            </div>
          </div>

          <div className="bg-indigo-900/10 border border-indigo-500/20 p-4 rounded-xl flex gap-3">
             <CheckCircle2 className="w-5 h-5 text-indigo-400 shrink-0" />
             <p className="text-xs text-indigo-200 leading-relaxed">
               <strong>Local Persistence:</strong> Changes to the port matrix are saved to your browser's local storage. This data is never sent to the cloud.
             </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
