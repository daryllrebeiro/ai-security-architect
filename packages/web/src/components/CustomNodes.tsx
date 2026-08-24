import React, { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  Globe,
  Server,
  Layers,
  Box,
  Key,
  Database,
  ShieldAlert,
  Crown,
  Network,
  Cpu,
  Flame,
} from 'lucide-react';
import type { SecurityNodeData } from '../utils/graph-converter.js';

const ASSET_ICONS: Record<string, React.ElementType> = {
  INTERNET: Globe,
  LOAD_BALANCER: Network,
  SERVICE: Server,
  API_CONTROLLER: Layers,
  ENDPOINT: Cpu,
  POD: Box,
  CONTAINER: Box,
  KUBERNETES_SERVICE: Network,
  KUBERNETES_SERVICE_ACCOUNT: Key,
  IAM_ROLE: Key,
  SERVICE_ACCOUNT: Key,
  BUCKET: Database,
  DATABASE: Database,
  SECRET: Key,
};

export const SecurityAssetNode = memo(({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as SecurityNodeData;
  const { asset, findings, isOnAttackPath, isEntryPoint, isCrownJewel, isChokePointSource } = nodeData;

  const IconComponent = ASSET_ICONS[asset.type] || Server;
  const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL');
  const highFindings = findings.filter((f) => f.severity === 'HIGH');

  let borderColor = 'rgba(255, 255, 255, 0.12)';
  let glowClass = '';

  if (isCrownJewel) {
    borderColor = '#ec4899';
  }
  if (isOnAttackPath) {
    borderColor = '#ef4444';
    glowClass = 'pulse-critical';
  } else if (selected) {
    borderColor = '#38bdf8';
  }

  return (
    <div
      style={{
        width: 220,
        backgroundColor: '#111827',
        border: `1.5px solid ${borderColor}`,
        borderRadius: 10,
        padding: '12px 14px',
        color: '#f8fafc',
        boxShadow: isOnAttackPath ? '0 0 20px rgba(239, 68, 68, 0.4)' : '0 4px 16px rgba(0,0,0,0.4)',
        cursor: 'pointer',
        transition: 'all 0.2s ease',
      }}
      className={glowClass}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#38bdf8', width: 8, height: 8 }} />

      {/* Header with Type Badge and Icons */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div
            style={{
              padding: 5,
              borderRadius: 6,
              background: isCrownJewel ? 'rgba(236, 72, 153, 0.2)' : 'rgba(56, 189, 248, 0.15)',
              color: isCrownJewel ? '#f472b6' : '#38bdf8',
            }}
          >
            <IconComponent size={15} />
          </div>
          <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.05em', color: '#94a3b8' }}>
            {asset.type.replace(/_/g, ' ')}
          </span>
        </div>

        {isCrownJewel && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 3,
              background: 'rgba(236, 72, 153, 0.25)',
              color: '#f472b6',
              padding: '2px 6px',
              borderRadius: 12,
              fontSize: 9,
              fontWeight: 700,
            }}
          >
            <Crown size={10} />
            PII
          </div>
        )}

        {isEntryPoint && !isCrownJewel && (
          <div
            style={{
              background: 'rgba(56, 189, 248, 0.25)',
              color: '#38bdf8',
              padding: '2px 6px',
              borderRadius: 12,
              fontSize: 9,
              fontWeight: 700,
            }}
          >
            ENTRY
          </div>
        )}
      </div>

      {/* Asset Name */}
      <div
        style={{
          fontSize: 12,
          fontWeight: 600,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          color: '#f8fafc',
          marginBottom: 6,
        }}
        title={asset.name}
      >
        {asset.name}
      </div>

      {/* Choke Point Highlight Alert */}
      {isChokePointSource && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 4,
            background: 'rgba(249, 115, 22, 0.2)',
            border: '1px solid #f97316',
            borderRadius: 4,
            padding: '2px 6px',
            fontSize: 9,
            fontWeight: 700,
            color: '#fb923c',
            marginBottom: 6,
          }}
        >
          <Flame size={10} />
          CHOKE POINT
        </div>
      )}

      {/* Findings Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 10, color: '#94a3b8' }}>
        <span>Env: {asset.environment}</span>

        {findings.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <ShieldAlert size={12} color={criticalFindings.length > 0 ? '#ef4444' : '#f97316'} />
            <span
              style={{
                fontWeight: 700,
                color: criticalFindings.length > 0 ? '#ef4444' : '#f97316',
              }}
            >
              {findings.length} finding{findings.length > 1 ? 's' : ''}
            </span>
          </div>
        )}
      </div>

      <Handle type="source" position={Position.Right} style={{ background: '#38bdf8', width: 8, height: 8 }} />
    </div>
  );
});

export const nodeTypes = {
  securityAsset: SecurityAssetNode,
};
