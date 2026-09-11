export interface VendorAttestation {
  vendorId: string;
  vendorName: string;
  matchedDomains: string[];
  certifications: string[]; // e.g. ["SOC2_TYPE_II", "ISO_27001"]
  hasPublicBreachHistory: boolean;
  questionnaireScore?: number; // 0 - 100
  riskTier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export const VENDOR_PROVENANCE_LABEL =
  '(Externally-Sourced Vendor Assessment, not an empirical topology finding)';

export interface VendorRiskSummary {
  vendorId: string;
  vendorName: string;
  transfersSensitiveData: boolean;
  riskTier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  fairLossMultiplier: number;
  certifications: string[];
  hasBreachHistory: boolean;
  provenanceLabel: string;
}
