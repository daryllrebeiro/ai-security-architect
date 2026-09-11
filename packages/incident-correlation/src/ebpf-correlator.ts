import type { AttackPath, Asset } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';

export type EbpfEventType =
  | 'PROCESS_EXEC'
  | 'SOCKET_CONNECT'
  | 'CAPABILITY_OVERRIDE'
  | 'FILE_INTEGRITY';

export interface EbpfEvent {
  eventId: string;
  timestamp: string;
  eventType: EbpfEventType;
  sourceWorkload: string; // Container name, pod, or host
  processName?: string;
  commandLine?: string;
  destinationIp?: string;
  destinationPort?: number;
  destinationHost?: string;
  rawPayloadSummary?: string;
}

export type ExploitStatus = 'ACTIVE_EXPLOIT' | 'PROBABLE_EXPLOIT' | 'RECONNAISSANCE';

export interface CorrelatedPathEvidence {
  attackPathId: string;
  entryAssetId: string;
  targetAssetId: string;
  exploitStatus: ExploitStatus;
  confidenceScore: number; // 0.0 - 1.0
  matchedHops: Array<{
    sourceAssetId: string;
    targetAssetId: string;
    triggeringEventId: string;
    triggeringEventType: EbpfEventType;
    detail: string;
  }>;
  suggestedContainment: string;
}

export interface EbpfCorrelationReport {
  timestamp: string;
  totalEventsAnalyzed: number;
  activeExploitationsCount: number;
  correlatedPaths: CorrelatedPathEvidence[];
  label: string;
}

export const EBPF_DISCLOSURE_LABEL =
  '(RUNTIME KERNEL CORRELATION: Correlated via in-process eBPF socket and process telemetry. Observational telemetry only; does not inject kernel modules directly)';

export class EbpfTrajectoryCorrelator {
  public correlate(
    events: EbpfEvent[],
    attackPaths: AttackPath[],
    graph: SecurityGraphEngine
  ): EbpfCorrelationReport {
    const timestamp = new Date().toISOString();
    const correlatedPaths: CorrelatedPathEvidence[] = [];

    // Map graph assets by name and IP for fast lookup
    const allNodes = graph.getAllNodes();
    const assetById = new Map<string, Asset>();
    const assetByName = new Map<string, Asset>();

    for (const node of allNodes) {
      assetById.set(node.asset.id, node.asset);
      assetByName.set(node.asset.name.toLowerCase(), node.asset);
    }

    for (const path of attackPaths) {
      const matchedHops: CorrelatedPathEvidence['matchedHops'] = [];

      for (const step of path.steps) {
        const sourceAsset = assetById.get(step.sourceAssetId);
        const targetAsset = assetById.get(step.targetAssetId);

        const sourceName = (sourceAsset?.name || step.sourceAssetId).toLowerCase();
        const targetName = (targetAsset?.name || step.targetAssetId).toLowerCase();

        for (const event of events) {
          const eventSrc = event.sourceWorkload.toLowerCase();
          const eventDstHost = (event.destinationHost || '').toLowerCase();
          const eventCmd = (event.commandLine || event.processName || '').toLowerCase();

          // Check if event source matches step source
          const isSourceMatch =
            eventSrc.includes(sourceName) ||
            sourceName.includes(eventSrc) ||
            step.sourceAssetId.toLowerCase().includes(eventSrc);

          if (!isSourceMatch) continue;

          // Process execution anomaly (e.g. curl, bash, sh, nmap, python inside workload)
          if (
            event.eventType === 'PROCESS_EXEC' &&
            /curl|wget|bash|sh|nmap|netcat|nc|socat|python/i.test(eventCmd)
          ) {
            matchedHops.push({
              sourceAssetId: step.sourceAssetId,
              targetAssetId: step.targetAssetId,
              triggeringEventId: event.eventId,
              triggeringEventType: event.eventType,
              detail: `Unexpected shell execution detected on workload (${eventCmd}) matching pivot hop`,
            });
          }

          // Socket connection anomaly to target asset
          if (
            event.eventType === 'SOCKET_CONNECT' &&
            (eventDstHost.includes(targetName) ||
              targetName.includes(eventDstHost) ||
              step.targetAssetId.toLowerCase().includes(eventDstHost))
          ) {
            matchedHops.push({
              sourceAssetId: step.sourceAssetId,
              targetAssetId: step.targetAssetId,
              triggeringEventId: event.eventId,
              triggeringEventType: event.eventType,
              detail: `Active TCP socket connection to ${eventDstHost}:${event.destinationPort || 'any'} traversed static attack hop`,
            });
          }
        }
      }

      if (matchedHops.length > 0) {
        // Calculate confidence based on matched hops vs total steps
        const hopRatio = matchedHops.length / Math.max(1, path.steps.length);
        let confidenceScore = Math.min(1.0, 0.4 + hopRatio * 0.6);
        let exploitStatus: ExploitStatus = 'RECONNAISSANCE';

        if (confidenceScore >= 0.8 || matchedHops.length >= 2) {
          exploitStatus = 'ACTIVE_EXPLOIT';
          confidenceScore = Math.max(0.85, confidenceScore);
        } else if (confidenceScore >= 0.5) {
          exploitStatus = 'PROBABLE_EXPLOIT';
        }

        const targetNode = assetById.get(path.targetAssetId);
        const targetLabel = targetNode?.name || path.targetAssetId;

        const suggestedContainment =
          exploitStatus === 'ACTIVE_EXPLOIT'
            ? `URGENT: Apply Tetragon SIGKILL / Cilium NetworkPolicy isolation on workload ${matchedHops[0].sourceAssetId} immediately to isolate crown jewel ${targetLabel}.`
            : `MONITOR: Restrict ingress security group on ${matchedHops[0].sourceAssetId} and inspect pod logs.`;

        correlatedPaths.push({
          attackPathId: path.id,
          entryAssetId: path.entryAssetId,
          targetAssetId: path.targetAssetId,
          exploitStatus,
          confidenceScore: Math.round(confidenceScore * 100) / 100,
          matchedHops,
          suggestedContainment,
        });
      }
    }

    const activeExploitationsCount = correlatedPaths.filter(
      (p) => p.exploitStatus === 'ACTIVE_EXPLOIT'
    ).length;

    return {
      timestamp,
      totalEventsAnalyzed: events.length,
      activeExploitationsCount,
      correlatedPaths,
      label: EBPF_DISCLOSURE_LABEL,
    };
  }
}
