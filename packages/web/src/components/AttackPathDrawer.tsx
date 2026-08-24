import React from 'react';
import {
  Flame,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  ShieldCheck,
  Zap,
  ArrowRight,
} from 'lucide-react';
import type { AttackPath } from '@ai-security-architect/core';

interface AttackPathDrawerProps {
  attackPaths: AttackPath[];
  selectedPathId?: string;
  onSelectPath: (pathId: string) => void;
  isRemediationSimulated: boolean;
  onToggleSimulateRemediation: () => void;
  onSelectStepAsset?: (assetId: string) => void;
}

export const AttackPathDrawer: React.FC<AttackPathDrawerProps> = ({
  attackPaths,
  selectedPathId,
  onSelectPath,
  isRemediationSimulated,
  onToggleSimulateRemediation,
  onSelectStepAsset,
}) => {
  const currentPath = attackPaths.find((p) => p.id === selectedPathId) || attackPaths[0];

  return (
    <div
      style={{
        width: 380,
        height: '100%',
        backgroundColor: '#0f172a',
        borderLeft: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={18} color="#ef4444" />
            <h2 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: '#f8fafc' }}>
              Attack Paths ({attackPaths.length})
            </h2>
          </div>
          {currentPath && (
            <div
              style={{
                background: 'rgba(239, 68, 68, 0.2)',
                border: '1px solid #ef4444',
                color: '#f87171',
                padding: '2px 8px',
                borderRadius: 12,
                fontSize: 12,
                fontWeight: 700,
              }}
            >
              Risk: {currentPath.riskScore.totalRisk}/10
            </div>
          )}
        </div>
        <p style={{ fontSize: 12, color: '#94a3b8', margin: 0 }}>
          Exploit chains discovered from public entry to crown jewels.
        </p>
      </div>

      {/* Path List Tabs */}
      {attackPaths.length > 1 && (
        <div style={{ display: 'flex', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', overflowX: 'auto' }}>
          {attackPaths.map((path) => (
            <button
              key={path.id}
              onClick={() => onSelectPath(path.id)}
              style={{
                padding: '8px 14px',
                background: selectedPathId === path.id ? '#1e293b' : 'transparent',
                border: 'none',
                borderBottom: selectedPathId === path.id ? '2px solid #38bdf8' : 'none',
                color: selectedPathId === path.id ? '#38bdf8' : '#94a3b8',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              Path #{path.id.replace('path-', '')} ({path.riskScore.totalRisk})
            </button>
          ))}
        </div>
      )}

      {/* Main Drawer Scroll Area */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
        {/* Recommended Choke Point Card */}
        {currentPath?.recommendedChokePoint && (
          <div
            style={{
              background: 'linear-gradient(135deg, rgba(249, 115, 22, 0.15), rgba(239, 68, 68, 0.1))',
              border: '1.5px solid #f97316',
              borderRadius: 10,
              padding: 14,
              marginBottom: 20,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Flame size={16} color="#fb923c" />
                <span style={{ fontSize: 13, fontWeight: 700, color: '#fb923c' }}>
                  Recommended Choke Point
                </span>
              </div>
              <span
                style={{
                  background: 'rgba(16, 185, 129, 0.2)',
                  color: '#34d399',
                  padding: '2px 6px',
                  borderRadius: 6,
                  fontSize: 10,
                  fontWeight: 700,
                }}
              >
                -{currentPath.recommendedChokePoint.riskReductionPercentage}% Risk
              </span>
            </div>

            <p style={{ fontSize: 12, color: '#f8fafc', lineHeight: 1.4, margin: '0 0 10px 0' }}>
              {currentPath.recommendedChokePoint.actionDescription}
            </p>

            <div style={{ display: 'flex', gap: 10, fontSize: 11, color: '#94a3b8', marginBottom: 12 }}>
              <span>Effort: <strong style={{ color: '#f8fafc' }}>{currentPath.recommendedChokePoint.engineeringEffort}</strong></span>
              <span>Blast Radius: <strong style={{ color: '#f8fafc' }}>{currentPath.recommendedChokePoint.blastRadius}</strong></span>
            </div>

            <button
              onClick={onToggleSimulateRemediation}
              style={{
                width: '100%',
                padding: '8px 12px',
                background: isRemediationSimulated ? '#10b981' : '#f97316',
                border: 'none',
                borderRadius: 6,
                color: '#ffffff',
                fontSize: 12,
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
                cursor: 'pointer',
                transition: 'background 0.2s',
              }}
            >
              {isRemediationSimulated ? (
                <>
                  <ShieldCheck size={14} />
                  Remediation Applied (Path Broken)
                </>
              ) : (
                <>
                  <Zap size={14} />
                  Simulate Remediation (Sever Edge)
                </>
              )}
            </button>
          </div>
        )}

        {/* Risk Breakdown */}
        {currentPath && (
          <div style={{ marginBottom: 20 }}>
            <h4 style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', margin: '0 0 8px 0' }}>
              Explainable Risk Breakdown
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div style={{ background: '#1e293b', padding: '8px 10px', borderRadius: 6 }}>
                <span style={{ fontSize: 10, color: '#94a3b8' }}>Impact</span>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc' }}>
                  {currentPath.riskScore.impact} / 10
                </div>
              </div>
              <div style={{ background: '#1e293b', padding: '8px 10px', borderRadius: 6 }}>
                <span style={{ fontSize: 10, color: '#94a3b8' }}>Exploitability</span>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc' }}>
                  {currentPath.riskScore.exploitability} / 10
                </div>
              </div>
              <div style={{ background: '#1e293b', padding: '8px 10px', borderRadius: 6 }}>
                <span style={{ fontSize: 10, color: '#94a3b8' }}>Reachability</span>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#38bdf8' }}>
                  {currentPath.riskScore.reachability * 100}%
                </div>
              </div>
              <div style={{ background: '#1e293b', padding: '8px 10px', borderRadius: 6 }}>
                <span style={{ fontSize: 10, color: '#94a3b8' }}>Target Criticality</span>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#ec4899' }}>
                  {currentPath.riskScore.assetCriticality} / 10
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Step-by-Step Exploit Progression */}
        {currentPath && (
          <div>
            <h4 style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', color: '#64748b', margin: '0 0 10px 0' }}>
              Exploit Progression ({currentPath.steps.length} Steps)
            </h4>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {currentPath.steps.map((step) => (
                <div
                  key={step.stepNumber}
                  style={{
                    background: '#1e293b',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                    borderRadius: 8,
                    padding: '10px 12px',
                    position: 'relative',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span
                        style={{
                          width: 18,
                          height: 18,
                          borderRadius: 9,
                          background: '#ef4444',
                          color: '#fff',
                          fontSize: 10,
                          fontWeight: 700,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                      >
                        {step.stepNumber}
                      </span>
                      <span style={{ fontSize: 11, fontWeight: 700, color: '#38bdf8' }}>
                        {step.relationshipType.replace(/_/g, ' ')}
                      </span>
                    </div>

                    {step.findingId && (
                      <span
                        style={{
                          background: 'rgba(239, 68, 68, 0.2)',
                          color: '#f87171',
                          padding: '1px 5px',
                          borderRadius: 4,
                          fontSize: 9,
                          fontWeight: 700,
                        }}
                      >
                        VULN
                      </span>
                    )}
                  </div>

                  <p style={{ fontSize: 11, color: '#cbd5e1', lineHeight: 1.35, margin: '4px 0 8px 0' }}>
                    {step.explanation}
                  </p>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: '#94a3b8' }}>
                    <button
                      onClick={() => onSelectStepAsset && onSelectStepAsset(step.sourceAssetId)}
                      style={{
                        background: 'none',
                        border: 'none',
                        padding: 0,
                        color: '#60a5fa',
                        fontSize: 10,
                        cursor: 'pointer',
                        textDecoration: 'underline',
                      }}
                    >
                      {step.sourceAssetId}
                    </button>
                    <ArrowRight size={10} />
                    <button
                      onClick={() => onSelectStepAsset && onSelectStepAsset(step.targetAssetId)}
                      style={{
                        background: 'none',
                        border: 'none',
                        padding: 0,
                        color: '#60a5fa',
                        fontSize: 10,
                        cursor: 'pointer',
                        textDecoration: 'underline',
                      }}
                    >
                      {step.targetAssetId}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
