import React, { useState, useRef } from 'react';
import { Upload, FileText, CheckCircle, AlertCircle, RefreshCcw } from 'lucide-react';
import { FirewallRule, ColumnMapping } from '../types';
import { DEFAULT_MAPPINGS } from '../constants';

interface UploaderProps {
  onDataLoaded: (rules: FirewallRule[]) => void;
}

const Uploader: React.FC<UploaderProps> = ({ onDataLoaded }) => {
  const [file, setFile] = useState<File | null>(null);
  const [headers, setHeaders] = useState<string[]>([]);
  const [mapping, setMapping] = useState<Partial<ColumnMapping>>({});
  const [rows, setRows] = useState<any[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (!selectedFile) return;

    setFile(selectedFile);
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      const lines = text.split(/\r?\n/);
      if (lines.length === 0) return;

      const csvHeaders = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
      setHeaders(csvHeaders);

      // Perform auto-mapping
      const initialMapping: Partial<ColumnMapping> = {};
      DEFAULT_MAPPINGS.forEach(m => {
        const found = csvHeaders.find(h => 
          m.synonyms.some(syn => h.toLowerCase().includes(syn.toLowerCase()))
        );
        if (found) {
          (initialMapping as any)[m.field] = found;
        }
      });
      setMapping(initialMapping);

      // Parse first few rows for validation/preview
      const parsedRows = lines.slice(1).filter(l => l.trim()).map(line => {
        const values = line.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
        const obj: any = {};
        csvHeaders.forEach((h, i) => {
          obj[h] = values[i] || '';
        });
        return obj;
      });
      setRows(parsedRows);
    };
    reader.readAsText(selectedFile);
  };

  const processData = () => {
    setIsProcessing(true);
    setTimeout(() => {
      const finalRules: FirewallRule[] = rows.map((row, idx) => {
        const getVal = (field: keyof ColumnMapping) => row[mapping[field] as string] || '';
        
        return {
          id: getVal('id') || (idx + 1).toString(),
          name: getVal('name') || `Rule ${idx + 1}`,
          source: getVal('source') || 'any',
          destination: getVal('destination') || 'any',
          sourcePort: getVal('sourcePort') || 'any',
          destinationPort: getVal('destinationPort') || 'any',
          service: getVal('description') || '',
          protocol: (getVal('protocol').toUpperCase() || 'ANY') as any,
          action: (getVal('action').toUpperCase().includes('ALLOW') || getVal('action').toUpperCase().includes('PERMIT')) ? 'ALLOW' : 'DENY',
          direction: getVal('direction').toUpperCase() || 'UNKNOWN',
          enabled: !getVal('enabled').toLowerCase().includes('false') && !getVal('enabled').toLowerCase().includes('no') && !getVal('enabled').toLowerCase().includes('disabled'),
          description: getVal('description'),
          originalRow: row
        };
      });
      onDataLoaded(finalRules);
      setIsProcessing(false);
    }, 500);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {!file ? (
        <div 
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-slate-700 bg-slate-900/50 rounded-2xl p-16 flex flex-col items-center justify-center cursor-pointer hover:border-indigo-500 hover:bg-slate-900 transition-all group"
        >
          <div className="bg-slate-800 p-4 rounded-full mb-4 group-hover:scale-110 transition-transform">
            <Upload className="w-8 h-8 text-indigo-400" />
          </div>
          <h2 className="text-xl font-semibold mb-2">Import Policy CSV</h2>
          <p className="text-slate-400 text-center max-w-sm">
            Drag and drop your firewall rule export (CSV) here. We'll automatically map the columns for analysis.
          </p>
          <input 
            type="file" 
            ref={fileInputRef} 
            className="hidden" 
            accept=".csv" 
            onChange={handleFileChange} 
          />
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FileText className="w-6 h-6 text-indigo-400" />
              <div>
                <h3 className="font-semibold text-lg">{file.name}</h3>
                <p className="text-xs text-slate-400">{rows.length} records detected</p>
              </div>
            </div>
            <button 
                onClick={() => setFile(null)}
                className="text-slate-400 hover:text-white flex items-center gap-1 text-sm font-medium"
            >
              <RefreshCcw className="w-4 h-4" /> Reset
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <h4 className="text-sm font-bold uppercase tracking-widest text-slate-500 flex items-center gap-2">
                <CheckCircle className="w-4 h-4" /> Verify Mapping
              </h4>
              <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2">
                {DEFAULT_MAPPINGS.map(m => (
                  <div key={m.field} className="flex flex-col gap-1">
                    <label className="text-xs font-semibold text-slate-400 capitalize">{m.field}</label>
                    <select 
                      value={mapping[m.field as keyof ColumnMapping] || ''} 
                      onChange={(e) => setMapping({...mapping, [m.field]: e.target.value})}
                      className="bg-slate-800 border border-slate-700 rounded-md px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:outline-none"
                    >
                      <option value="">-- Ignored --</option>
                      {headers.map(h => (
                        <option key={h} value={h}>{h}</option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              <h4 className="text-sm font-bold uppercase tracking-widest text-slate-500 flex items-center gap-2">
                <AlertCircle className="w-4 h-4" /> CSV Preview
              </h4>
              <div className="bg-slate-950 rounded-lg p-4 font-mono text-xs overflow-x-auto border border-slate-800">
                <table className="w-full text-left">
                  <thead>
                    <tr>
                      {headers.slice(0, 4).map(h => <th key={h} className="pb-2 text-slate-500">{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.slice(0, 5).map((row, i) => (
                      <tr key={i} className="border-t border-slate-800">
                        {headers.slice(0, 4).map(h => <td key={h} className="py-2 text-slate-300 max-w-[100px] truncate">{row[h]}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="p-4 bg-indigo-900/20 border border-indigo-500/30 rounded-xl">
                 <p className="text-sm text-indigo-200">
                   RuleGuardX uses <strong>local execution</strong>. Your firewall configuration is never sent to any external server or API.
                 </p>
              </div>
              <button 
                onClick={processData}
                disabled={isProcessing}
                className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-4 rounded-xl shadow-lg shadow-indigo-500/20 transition-all active:scale-95 disabled:opacity-50"
              >
                {isProcessing ? 'Analyzing Engine Logic...' : 'Launch Security Analysis'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Uploader;