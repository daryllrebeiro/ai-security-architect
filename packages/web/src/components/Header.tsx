import React from 'react';
import { Shield, ShieldAlert, Layers, Search, RefreshCw, Sparkles, Lock } from 'lucide-react';

interface HeaderProps {
  totalAssets: number;
  totalPaths: number;
  highestRiskScore: number;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onResetGraph: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  totalAssets,
  totalPaths,
  highestRiskScore,
  searchQuery,
  onSearchChange,
  onResetGraph,
}) => {
  return (
    <header
      style={{
        height: 60,
        backgroundColor: '#0f172a',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 20px',
        zIndex: 30,
      }}
    >
      {/* Brand & Title */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div
          style={{
            width: 34,
            height: 34,
            borderRadius: 8,
            background: 'linear-gradient(135deg, #6366f1, #3b82f6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#ffffff',
            boxShadow: '0 0 15px rgba(99, 102, 241, 0.4)',
          }}
        >
          <Shield size={20} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <h1 style={{ fontSize: 16, fontWeight: 800, margin: 0, letterSpacing: '-0.02em', color: '#f8fafc' }}>
              AI Security Architect
            </h1>
            <span
              style={{
                background: 'rgba(99, 102, 241, 0.2)',
                border: '1px solid rgba(99, 102, 241, 0.4)',
                color: '#818cf8',
                fontSize: 10,
                fontWeight: 700,
                padding: '1px 6px',
                borderRadius: 4,
              }}
            >
              CANVAS v1.0
            </span>
          </div>
          <span style={{ fontSize: 11, color: '#64748b' }}>
            Deterministic Graph & Attack-Path Reasoning Platform
          </span>
        </div>
      </div>

      {/* Metrics Bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: '#1e293b', padding: '6px 12px', borderRadius: 6 }}>
          <Layers size={14} color="#38bdf8" />
          <span style={{ fontSize: 12, color: '#94a3b8' }}>Assets:</span>
          <strong style={{ fontSize: 12, color: '#f8fafc' }}>{totalAssets}</strong>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: '#1e293b', padding: '6px 12px', borderRadius: 6 }}>
          <ShieldAlert size={14} color="#ef4444" />
          <span style={{ fontSize: 12, color: '#94a3b8' }}>Attack Paths:</span>
          <strong style={{ fontSize: 12, color: '#ef4444' }}>{totalPaths}</strong>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', padding: '6px 12px', borderRadius: 6 }}>
          <span style={{ fontSize: 12, color: '#fca5a5' }}>Peak Risk:</span>
          <strong style={{ fontSize: 13, color: '#ef4444' }}>{highestRiskScore} / 10</strong>
        </div>
      </div>

      {/* Controls & Search */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ position: 'relative' }}>
          <Search size={14} color="#64748b" style={{ position: 'absolute', left: 10, top: 10 }} />
          <input
            type="text"
            placeholder="Search assets, endpoints, CVEs..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            style={{
              background: '#1e293b',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: 6,
              padding: '6px 10px 6px 30px',
              color: '#f8fafc',
              fontSize: 12,
              width: 240,
              outline: 'none',
            }}
          />
        </div>

        <button
          onClick={onResetGraph}
          title="Reset Graph Layout"
          style={{
            background: '#1e293b',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: 6,
            padding: 7,
            color: '#94a3b8',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <RefreshCw size={14} />
        </button>
      </div>
    </header>
  );
};
