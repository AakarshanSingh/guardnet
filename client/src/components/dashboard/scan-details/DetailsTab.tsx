import React, { JSX } from 'react';
import { formatToIST } from '../../../context/ScanContext';
import DNSInformation from './DNSInformation';
import PortInformation from './PortInformation';
import DirectoryScan from './DirectoryScan';
import LFIVulnerability from './LFIVulnerability';
import CommandInjectionVulnerability from './CommandInjectionVulnerability';
import SQLInjectionVulnerability from './SQLInjectionVulnerability';

interface CurrentScan {
  id: string;
  website_id: string;
  website?: {
    id: string;
    url: string;
    user_id: string;
    created_at: string;
    cookies?: string;
  };
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  created_at: string;
  summary?: {
    total_issues_found: number;
    high_severity_issues: number;
    medium_severity_issues: number;
    low_severity_issues: number;
    scan_completed: boolean;
    scan_status: string;
    scan_started_at: string;
    scan_completed_at: string;
  };
}

interface DetailsTabProps {
  currentScan: CurrentScan;
  scanId: string;
  results: Record<string, any> | null;
  extractDataFromResults: (scanType: string) => any;
}

const DetailsTab: React.FC<DetailsTabProps> = ({ 
  currentScan, 
  scanId, 
  results, 
  extractDataFromResults 
}) => {
  // Helper function to check if a specific scan result exists
  const hasScanType = (scanType: string): boolean => {
    if (!results || !scanId || !results[scanId]) return false;
    
    return results[scanId].some((r: any) => 
      r.scan_type === scanType || (r.result_data && r.result_data[scanType])
    );
  };

  // Vulnerability section component for consistent rendering
  const VulnerabilitySection = ({ 
    title, 
    icon, 
    condition, 
    children 
  }: { 
    title: string;
    icon: JSX.Element;
    condition: boolean;
    children: React.ReactNode;
  }) => {
    if (!condition) return null;
    
    return (
      <div className="bg-white/70 rounded-xl border border-indigo-100 p-5 shadow-sm">
        <h3 className="text-lg font-medium text-indigo-800 mb-4 flex items-center gap-2">
          {icon}
          {title}
        </h3>
        <div className="space-y-4">
          {children}
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Basic Scan Configuration */}
      <div className="bg-white/70 rounded-xl border border-indigo-100 p-5 shadow-sm">
        <h3 className="text-lg font-medium text-indigo-800 mb-4">Scan Configuration</h3>
        
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4">
            <div>
              <h4 className="text-sm font-medium text-indigo-600">Target URL</h4>
              <p className="text-indigo-900">{currentScan.website?.url || 'Not available'}</p>
            </div>
            
            <div>
              <h4 className="text-sm font-medium text-indigo-600">Status</h4>
              <p className="text-indigo-900">{currentScan.status.charAt(0).toUpperCase() + currentScan.status.slice(1)}</p>
            </div>
            
            <div>
              <h4 className="text-sm font-medium text-indigo-600">Created At</h4>
              <p className="text-indigo-900">
                {currentScan.created_at && formatToIST(currentScan.created_at)}
              </p>
            </div>
            
            {currentScan.started_at && (
              <div>
                <h4 className="text-sm font-medium text-indigo-600">Started At</h4>
                <p className="text-indigo-900">
                  {formatToIST(currentScan.started_at)}
                </p>
              </div>
            )}
            
            {currentScan.completed_at && (
              <div>
                <h4 className="text-sm font-medium text-indigo-600">Completed At</h4>
                <p className="text-indigo-900">
                  {formatToIST(currentScan.completed_at)}
                </p>
              </div>
            )}
            
            {/* If we have cookie info */}
            {currentScan.website?.cookies && (
              <div className="md:col-span-2">
                <h4 className="text-sm font-medium text-indigo-600 mb-1">Cookies Used</h4>
                <div className="bg-indigo-50/60 p-3 rounded-lg border border-indigo-100">
                  <pre className="text-sm text-indigo-700 overflow-x-auto whitespace-pre-wrap">
                    {currentScan.website.cookies}
                  </pre>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* Network Infrastructure Section */}
      <VulnerabilitySection
        title="Network Infrastructure"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2H5a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
          </svg>
        }
        condition={hasScanType('ports')}
      >
        <PortInformation portData={extractDataFromResults('ports')} />
      </VulnerabilitySection>
      
      {/* DNS Information Section */}
      <VulnerabilitySection
        title="DNS Configuration"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
          </svg>
        }
        condition={hasScanType('dns')}
      >
        <DNSInformation dnsData={extractDataFromResults('dns')} />
      </VulnerabilitySection>
      
      {/* Directory Scanning Section */}
      <VulnerabilitySection
        title="Directory Scanning"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
          </svg>
        }
        condition={hasScanType('directories')}
      >
        <DirectoryScan directoryData={extractDataFromResults('directories')} />
      </VulnerabilitySection>
      
      {/* LFI Vulnerabilities Section */}
      <VulnerabilitySection
        title="File Inclusion Vulnerabilities"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        }
        condition={hasScanType('lfi')}
      >
        <LFIVulnerability lfiData={extractDataFromResults('lfi')} />
      </VulnerabilitySection>
      
      {/* Command Injection Vulnerabilities Section */}
      <VulnerabilitySection
        title="Command Injection Vulnerabilities"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14-10a2 2 0 012 2v3a2 2 0 01-2 2H5a2 2 0 01-2-2V3a2 2 0 012-2h14z" />
          </svg>
        }
        condition={hasScanType('command_injection')}
      >
        <CommandInjectionVulnerability commandInjectionData={extractDataFromResults('command_injection')} />
      </VulnerabilitySection>
      
      {/* SQL Injection Vulnerabilities Section */}
      <VulnerabilitySection
        title="SQL Injection Vulnerabilities"
        icon={
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
          </svg>
        }
        condition={hasScanType('sqli')}
      >
        <SQLInjectionVulnerability sqliData={extractDataFromResults('sqli')} />
      </VulnerabilitySection>
    </div>
  );
};

export default DetailsTab;