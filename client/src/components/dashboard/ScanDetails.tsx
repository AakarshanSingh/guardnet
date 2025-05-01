import React, { useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router';
import { ScanContext, ScanResult } from '../../context/ScanContext';
import { AuthContext } from '../../context/AuthContext';

import ScanStatusCard from './scan-details/ScanStatusCard';
import OverviewTab from './scan-details/OverviewTab';
import VulnerabilitiesTab from './scan-details/VulnerabilitiesTab';
import DetailsTab from './scan-details/DetailsTab';
import { Vulnerability } from './scan-details/VulnerabilityItem';

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

interface ScanDetailsProps {
  scanId: string;
}

const ScanDetails: React.FC<ScanDetailsProps> = ({ scanId }) => {
  const { scans, results, getScanResults, getScanStatus, downloadReport } = useContext(ScanContext);
  const { isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();
  
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [currentScan, setCurrentScan] = useState<CurrentScan | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isDownloading, setIsDownloading] = useState<boolean>(false);
  
  // Extract vulnerabilities from scan results
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  
  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }

    const loadScanData = async () => {
      setLoading(true);
      if (!scanId) return;
      
      // Find scan in existing scans array
      const existingScan = scans.find(s => s.id === scanId);
      
      if (existingScan) {
        setCurrentScan(existingScan);
        
        // If the scan is completed, fetch results
        if (existingScan.status === 'completed' || existingScan.status === 'failed') {
          const scanResults = await getScanResults(scanId);
          processResults(scanResults);
        }
      } else {
        // If not found in context, fetch individually
        const status = await getScanStatus(scanId);
        if (status === 'completed' || status === 'failed') {
          const scanResults = await getScanResults(scanId);
          processResults(scanResults);
        }
      }
      
      setLoading(false);
    };
    
    loadScanData();
  }, [scanId, isAuthenticated]);
  
  const processResults = (scanResults: ScanResult[] | null) => {
    if (!scanResults) return;
    
    const allVulnerabilities: Vulnerability[] = [];
    
    // Process different scan results and extract vulnerabilities
    scanResults.forEach(result => {
      // Process WordPress scan results
      if (result.scan_type === 'wpscan' || (result.scan_type === 'wordpress' && result.result_data.vulnerabilities_found)) {
        const wpscanData = result.result_data;
        if (wpscanData.vulnerabilities_found && wpscanData.vulnerabilities_found.length > 0) {
          wpscanData.vulnerabilities_found.forEach((vuln: any) => {
            allVulnerabilities.push({
              type: 'WordPress',
              severity: getSeverity(vuln.cvss_score),
              description: vuln.title || 'WordPress Vulnerability',
              details: vuln.description
            });
          });
        }
      } 
      // Process XSS vulnerabilities
      else if (result.scan_type === 'xss' && result.result_data.vulnerable_endpoints) {
        result.result_data.vulnerable_endpoints.forEach((endpoint: any) => {
          allVulnerabilities.push({
            type: 'XSS',
            severity: 'high',
            description: `XSS in ${endpoint.url}`,
            details: `Payload: ${endpoint.payload || 'N/A'}`
          });
        });
      } 
      // Process SQL Injection vulnerabilities
      else if (result.scan_type === 'sqli') {
        // Handle sqli when it's an array (as in your scan results)
        if (Array.isArray(result.result_data)) {
          result.result_data.forEach((sqliItem) => {
            if (sqliItem.vulnerable_params && sqliItem.vulnerable_params.length > 0) {
              sqliItem.vulnerable_params.forEach((param: any) => {
                allVulnerabilities.push({
                  type: 'SQL Injection',
                  severity: 'high',
                  description: `SQLi in ${param.url}`,
                  details: `Parameter: ${param.parameter}, Type: ${param.type || 'Unknown'}, Payload: ${param.payload || 'N/A'}`
                });
              });
            }
          });
        } 
        // Handle when sqli is a single object (original format)
        else if (result.result_data.vulnerable_params) {
          result.result_data.vulnerable_params.forEach((param: any) => {
            allVulnerabilities.push({
              type: 'SQL Injection',
              severity: 'high',
              description: `SQLi in ${param.url}`,
              details: `Parameter: ${param.parameter}, DBMS: ${result.result_data.dbms_info || 'Unknown'}`
            });
          });
        }
      } 
      // Process SSL issues
      else if (result.scan_type === 'ssl' && result.result_data.issues_found) {
        result.result_data.issues_found.forEach((issue: any) => {
          allVulnerabilities.push({
            type: 'SSL',
            severity: getSeverity(issue.score),
            description: issue.title || 'SSL Issue',
            details: issue.description
          });
        });
      }
      // Process DNS misconfigurations
      else if (result.scan_type === 'dns' || (result.result_data && result.result_data.dns)) {
        const dnsData = result.scan_type === 'dns' ? result.result_data : result.result_data.dns;
        if (dnsData && dnsData.misconfigurations) {
          dnsData.misconfigurations.forEach((issue: any) => {
            allVulnerabilities.push({
              type: 'DNS',
              severity: issue.severity || 'medium',
              description: issue.title || 'DNS Misconfiguration',
              details: issue.description || ''
            });
          });
        }
      }
      // Process open ports as low severity findings
      else if (result.scan_type === 'ports' || (result.result_data && result.result_data.ports)) {
        const portsData = result.scan_type === 'ports' ? result.result_data : result.result_data.ports;
        if (portsData && portsData.open_ports) {
          portsData.open_ports.forEach((port: number) => {
            const service = portsData.services_detected ? portsData.services_detected[port.toString()] : 'Unknown';
            allVulnerabilities.push({
              type: 'Open Port',
              severity: 'low', // Most open ports are informational/low severity
              description: `Open Port ${port} (${service})`,
              details: `Service detected: ${service || 'Unknown'}`
            });
          });
        }
      }
      // Process LFI vulnerabilities
      else if (result.scan_type === 'lfi' || (result.result_data && result.result_data.lfi)) {
        const lfiData = result.scan_type === 'lfi' ? result.result_data : result.result_data.lfi;
        if (lfiData && lfiData.vulnerable_endpoints && lfiData.vulnerable_endpoints.length > 0) {
          lfiData.vulnerable_endpoints.forEach((endpoint: any) => {
            allVulnerabilities.push({
              type: 'LFI',
              severity: 'high',
              description: `Local File Inclusion vulnerability in ${endpoint.url || 'endpoint'}`,
              details: endpoint.details || 'The endpoint is vulnerable to Local File Inclusion attacks.'
            });
          });
        }
      }
      // Process zone transfer vulnerabilities
      else if (result.scan_type === 'zone_transfer' || (result.result_data && result.result_data.zone_transfer)) {
        const zoneData = result.scan_type === 'zone_transfer' ? result.result_data : result.result_data.zone_transfer;
        if (zoneData && zoneData.transferable_domains && zoneData.transferable_domains.length > 0) {
          zoneData.transferable_domains.forEach((domain: string) => {
            allVulnerabilities.push({
              type: 'Zone Transfer',
              severity: 'high',
              description: `DNS Zone Transfer possible for ${domain}`,
              details: 'DNS Zone Transfer allows attackers to obtain a copy of your entire DNS zone file.'
            });
          });
        }
        if (zoneData && zoneData.issues_found && zoneData.issues_found.length > 0) {
          zoneData.issues_found.forEach((issue: any) => {
            allVulnerabilities.push({
              type: 'Zone Transfer',
              severity: issue.severity || 'medium',
              description: issue.title || 'DNS Zone Issue',
              details: issue.description || ''
            });
          });
        }
      }
      // Process directory scanning results (sensitive files)
      else if (result.scan_type === 'directories' || (result.result_data && result.result_data.directories)) {
        const dirData = result.scan_type === 'directories' ? result.result_data : result.result_data.directories;
        if (dirData && dirData.sensitive_files_found && dirData.sensitive_files_found.length > 0) {
          dirData.sensitive_files_found.forEach((file: any) => {
            allVulnerabilities.push({
              type: 'Sensitive File',
              severity: 'medium',
              description: `Sensitive file found: ${file.path || file}`,
              details: file.description || 'This file may expose sensitive information or configurations.'
            });
          });
        }
      }
      // Process command injection vulnerabilities
      else if (result.scan_type === 'command_injection' && result.result_data.vulnerable_endpoints) {
        result.result_data.vulnerable_endpoints.forEach((endpoint: any) => {
          allVulnerabilities.push({
            type: 'Command Injection',
            severity: 'high',
            description: `Command Injection in ${endpoint.url || 'endpoint'}`,
            details: endpoint.details || `Successfully executed ${result.result_data.commands_executed?.length || 0} commands`
          });
        });
      }
      // Extract information from summary if available
      else if (result.scan_type === 'summary' && result.result_data) {
        // We'll use summary data to update the scan state but not add it as a vulnerability
        if (currentScan) {
          setCurrentScan((prev: CurrentScan | null) => {
            if (prev === null) return null;
            return {
              ...prev,
              summary: result.result_data
            };
          });
        }
      }
    });
    
    // Sort vulnerabilities by severity: high -> medium -> low
    const severityOrder = { high: 0, medium: 1, low: 2 };
    const sortedVulnerabilities = allVulnerabilities.sort((a, b) => 
      severityOrder[a.severity] - severityOrder[b.severity]
    );
    
    setVulnerabilities(sortedVulnerabilities);
  };
  
  const getSeverity = (score?: number): 'high' | 'medium' | 'low' => {
    if (!score) return 'medium';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  };
  
  const refreshStatus = async () => {
    if (!scanId) return;
    setIsRefreshing(true);
    
    await getScanStatus(scanId);
    
    // If status is completed, fetch results
    const updatedScan = scans.find(s => s.id === scanId);
    if (updatedScan) {
      setCurrentScan(updatedScan);
    }
    
    if (updatedScan?.status === 'completed') {
      const scanResults = await getScanResults(scanId);
      processResults(scanResults);
    }
    
    setIsRefreshing(false);
  };
  
  const handleDownloadReport = async (format: 'pdf' | 'excel') => {
    if (!scanId) return;
    setIsDownloading(true);
    try {
      await downloadReport(scanId, format);
    } finally {
      setIsDownloading(false);
    }
  };
  
  // Extract data for specialized components
  const extractDataFromResults = (scanType: string) => {
    if (!results || !scanId || !results[scanId]) return null;
    
    const result = results[scanId].find(r => 
      r.scan_type === scanType || (r.result_data && r.result_data[scanType])
    );
    
    if (!result) return null;
    return result.scan_type === scanType ? result.result_data : result.result_data[scanType];
  };

  if (!isAuthenticated) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh]">
        <div className="text-center max-w-md">
          <svg xmlns="http://www.w3.org/2000/svg" className="h-16 w-16 mx-auto text-indigo-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <h2 className="text-2xl font-bold text-indigo-800 mb-2">Authentication Required</h2>
          <p className="text-indigo-600 mb-6">Please log in to view scan details.</p>
        </div>
      </div>
    );
  }
  
  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-[50vh]">
        <div className="flex flex-col items-center">
          <svg className="animate-spin h-12 w-12 text-indigo-500 mb-3" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <span className="text-indigo-700">Loading scan details...</span>
        </div>
      </div>
    );
  }
  
  if (!currentScan) {
    return (
      <div className="backdrop-blur-sm bg-white/50 border border-red-100 rounded-2xl p-8 text-center shadow-md">
        <svg xmlns="http://www.w3.org/2000/svg" className="h-16 w-16 mx-auto text-red-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <h2 className="text-2xl font-bold text-red-800 mb-2">Scan Not Found</h2>
        <p className="text-red-600 mb-6">We couldn't find the scan you're looking for.</p>
        <button
          onClick={() => navigate('/dashboard')}
          className="px-6 py-3 bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 text-white rounded-lg shadow-md hover:shadow-lg transition-all duration-200"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-[80vh]">
      {/* Header Section */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/dashboard')}
              className="p-2 rounded-lg bg-indigo-50 text-indigo-700 hover:bg-indigo-100"
              aria-label="Back to dashboard"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </button>
            <h1 className="text-2xl font-bold text-indigo-900">
              Scan Details
            </h1>
          </div>
          <p className="text-indigo-600 mt-1">
            {currentScan.website?.url || 'URL not available'}
          </p>
        </div>
      </div>
      
      {/* Scan Status Card - using our component */}
      <ScanStatusCard 
        scan={currentScan} 
        isRefreshing={isRefreshing}
        onRefresh={refreshStatus}
        onDownloadReport={handleDownloadReport}
        isDownloading={isDownloading}
      />
      
      {/* Tabs */}
      <div className="border-b border-indigo-200 mb-6">
        <nav className="-mb-px flex space-x-6">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3 border-b-2 font-medium text-sm ${
              activeTab === 'overview'
                ? 'border-indigo-500 text-indigo-600'
                : 'border-transparent text-indigo-400 hover:text-indigo-600'
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('vulnerabilities')}
            className={`py-3 border-b-2 font-medium text-sm flex items-center gap-2 ${
              activeTab === 'vulnerabilities'
                ? 'border-indigo-500 text-indigo-600'
                : 'border-transparent text-indigo-400 hover:text-indigo-600'
            }`}
          >
            Vulnerabilities
            {vulnerabilities.length > 0 && (
              <span className="bg-red-100 text-red-700 rounded-full text-xs py-0.5 px-2 border border-red-200">
                {vulnerabilities.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('details')}
            className={`py-3 border-b-2 font-medium text-sm ${
              activeTab === 'details'
                ? 'border-indigo-500 text-indigo-600'
                : 'border-transparent text-indigo-400 hover:text-indigo-600'
            }`}
          >
            Scan Details
          </button>
        </nav>
      </div>
      
      {/* Content */}
      <div className="min-h-[400px]">
        {activeTab === 'overview' && (
          <OverviewTab 
            vulnerabilities={vulnerabilities} 
            onViewAllVulnerabilities={() => setActiveTab('vulnerabilities')}
            scan={currentScan}
          />
        )}
        
        {activeTab === 'vulnerabilities' && (
          <VulnerabilitiesTab vulnerabilities={vulnerabilities} />
        )}
        
        {activeTab === 'details' && (
          <DetailsTab 
            currentScan={currentScan}
            scanId={scanId}
            results={results}
            extractDataFromResults={extractDataFromResults}
          />
        )}
      </div>
    </div>
  );
};

export default ScanDetails;