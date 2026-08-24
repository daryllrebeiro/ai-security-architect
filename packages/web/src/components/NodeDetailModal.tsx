import React from 'react';
import { X, ShieldAlert, FileCode, Hash, AlertOctagon, CheckCircle } from 'lucide-react';
import type { GraphNode } from '@ai-security-architect/graph';

interface NodeDetailModalProps {
  node?: GraphNode;
  onClose: () => void;
}

export const NodeDetailModal: React.FC<NodeDetailModalProps> = ({ node, onClose }) => {
  if (!node) return null;

  const { asset, findings } = node;

  return (
    <div
      style={{
        position: 'fixed',
        top: 60,
        right: 390,
        width: 440,
        maxHeight: 'calc(100vh - 80px)',
        backgroundColor: '#0f172a',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        borderRadius: 12,
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6)',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 50,
        overflow: 'hidden',
      }}
    >
      {/* Modal Header */}
      <div
        style={{
          padding: '14px 18px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <span style={{ fontSize: 10, fontWeight: 700, color: '#38bdf8', letterSpacing: '0.05em' }}>
            {asset.type.replace(/_/g, ' ')}
          </span>
          <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: '#f8fafc' }}>
            {asset.name}
          </h3>
        </div>
        <button
          onClick={onClose}
          style={{
            background: 'rgba(255, 255, 255, 0.05)',
            border: 'none',
            borderRadius: 6,
            padding: 6,
            color: '#94a3b8',
            cursor: 'pointer',
          }}
        >
          <X size={16} />
        </button>
      </div>

      {/* Modal Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 18px' }}>
        {/* Properties Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
          <div style={{ background: '#1e293b', padding: '8px 10px', borderRadius: 6 }}>
            <span style={{ fontSize: 10, color: '#94a3b8' }}>Environment</span>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#f8fafc' }}>{asset.environment}</div>
          </div>
          <div style={{ background: '#1e293b', padding: '8px 10px', borderRadius: 6 }}>
            <span style={{ fontSize: 10, color: '#94a3b8' }}>Criticality</span>
            <div
              style={{
                fontSize: 12,
                fontWeight: 700,
                color: asset.criticality === 'CRITICAL' ? '#ef4444' : '#f97316',
              }}
            >
              {asset.criticality}
            </div>
          </div>
          <div style={{ background: '#1e293b', padding: '8px 10px', borderRadius: 6 }}>
            <span style={{ fontSize: 10, color: '#94a3b8' }}>Public Exposure</span>
            <div style={{ fontSize: 12, fontWeight: 600, color: asset.isPublic ? '#ef4444' : '#10b981' }}>
              {asset.isPublic ? 'PUBLIC (Ingress)' : 'Private (Internal)'}
            </div>
          </div>
          <div style={{ background: '#1e293b', padding: '8px 10px', borderRadius: 6 }}>
            <span style={{ fontSize: 10, color: '#94a3b8' }}>Data Classification</span>
            <div style={{ fontSize: 12, fontWeight: 600, color: asset.isSensitiveData ? '#ec4899' : '#94a3b8' }}>
              {asset.isSensitiveData ? 'CONFIDENTIAL / PII' : 'Standard Asset'}
            </div>
          </div>
        </div>

        {/* Attached Security Findings */}
        <div style={{ marginBottom: 16 }}>
          <h4 style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', margin: '0 0 8px 0' }}>
            Security Findings ({findings.length})
          </h4>

          {findings.length === 0 ? (
            <div style={{ background: '#1e293b', padding: 12, borderRadius: 6, display: 'flex', alignItems: 'center', gap: 8, color: '#10b981', fontSize: 12 }}>
              <CheckCircle size={16} />
              No deterministic security findings detected on this asset.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {findings.map((f) => (
                <div
                  key={f.id}
                  style={{
                    background: '#1e293b',
                    border: `1px solid ${f.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(249, 115, 22, 0.4)'}`,
                    borderRadius: 8,
                    padding: 12,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span
                      style={{
                        background: f.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.25)' : 'rgba(249, 115, 22, 0.25)',
                        color: f.severity === 'CRITICAL' ? '#ef4444' : '#fb923c',
                        padding: '2px 6px',
                        borderRadius: 4,
                        fontSize: 10,
                        fontWeight: 700,
                      }}
                    >
                      {f.severity}
                    </span>
                    <span style={{ fontSize: 10, color: '#94a3b8' }}>Scanner: {f.scanner}</span>
                  </div>

                  <h5 style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', margin: '4px 0' }}>
                    {f.title}
                  </h5>
                  <p style={{ fontSize: 11, color: '#cbd5e1', lineHeight: 1.4, margin: '4px 0 8px 0' }}>
                    {f.description}
                  </p>

                  {/* Cryptographic Evidence Box */}
                  {f.evidence && (
                    <div
                      style={{
                        background: '#090d16',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: 6,
                        padding: '8px 10px',
                        fontSize: 10,
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#38bdf8', marginBottom: 4 }}>
                        <FileCode size={12} />
                        <span style={{ fontWeight: 600 }}>{f.evidence.filePath}:{f.evidence.lineStart}-{f.evidence.lineEnd}</span>
                      </div>
                      <pre
                        style={{
                          margin: '4px 0',
                          padding: 6,
                          background: 'rgba(0,0,0,0.5)',
                          borderRadius: 4,
                          color: '#e2e8f0',
                          fontSize: 10,
                          overflowX: 'auto',
                        }}
                      >
                        {f.evidence.snippet}
                      </pre>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#64748b', fontSize: 9 }}>
                        <Hash size={10} />
                        <span>SHA-256: {f.evidence.snippetSha256.substring(0, 24)}...</span>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
