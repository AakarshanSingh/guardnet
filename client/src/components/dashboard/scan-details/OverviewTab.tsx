import React from 'react';
import { Vulnerability } from './VulnerabilityItem';
import { formatToIST } from '../../../context/ScanContext';

interface OverviewTabProps {
  vulnerabilities: Vulnerability[];
  onViewAllVulnerabilities: () => void;
  scan: {
    id: string;
    status: string;
    created_at: string;
    started_at?: string;
    completed_at?: string;
    summary?: {
      total_issues_found: number;
      high_severity_issues: number;
      medium_severity_issues: number;
      low_severity_issues: number;
      scan_completed: boolean;
      scan_status: string;
      scan_started_at: string;
      scan_completed_at: string;
    }
  };
}

const OverviewTab: React.FC<OverviewTabProps> = ({ 
  vulnerabilities, 
  onViewAllVulnerabilities, 
  scan 
}) => {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'medium':
        return 'text-amber-600 bg-amber-50 border-amber-200';
      case 'low':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  // Use server-provided counts if available, otherwise fall back to client-side counting
  const highCount = scan.summary?.high_severity_issues ?? vulnerabilities.filter(v => v.severity === 'high').length;
  const mediumCount = scan.summary?.medium_severity_issues ?? vulnerabilities.filter(v => v.severity === 'medium').length;
  const lowCount = scan.summary?.low_severity_issues ?? vulnerabilities.filter(v => v.severity === 'low').length;
  const totalCount = scan.summary?.total_issues_found ?? vulnerabilities.length;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Summary Card */}
        <div className="bg-gradient-to-br from-white/90 to-indigo-50/90 rounded-xl border border-indigo-200/70 p-5 shadow-sm">
          <h3 className="text-lg font-medium text-indigo-800 mb-4 flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            Summary
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-4">
            <div className="bg-white/70 rounded-lg p-3 text-center border border-indigo-100">
              <span className="text-2xl font-bold text-indigo-700">
                {highCount}
              </span>
              <p className="text-xs text-red-600 mt-1">High</p>
            </div>
            <div className="bg-white/70 rounded-lg p-3 text-center border border-indigo-100">
              <span className="text-2xl font-bold text-indigo-700">
                {mediumCount}
              </span>
              <p className="text-xs text-amber-600 mt-1">Medium</p>
            </div>
            <div className="bg-white/70 rounded-lg p-3 text-center border border-indigo-100">
              <span className="text-2xl font-bold text-indigo-700">
                {lowCount}
              </span>
              <p className="text-xs text-blue-600 mt-1">Low</p>
            </div>
          </div>
          <div className="bg-white/70 rounded-lg p-3 text-center border border-indigo-100">
            <span className="text-3xl font-bold text-indigo-700">
              {totalCount}
            </span>
            <p className="text-sm text-indigo-600 mt-1">Total Issues</p>
          </div>
        </div>
        
        {/* Status Timeline */}
        <div className="md:col-span-2 bg-gradient-to-br from-white/90 to-indigo-50/90 rounded-xl border border-indigo-200/70 p-5 shadow-sm overflow-x-auto">
          <h3 className="text-lg font-medium text-indigo-800 mb-4 flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2M15 13a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            Scan Process
          </h3>
          <div className="relative">
            <div className="absolute h-full w-0.5 bg-indigo-200 left-2.5 top-0"></div>
            <div className="space-y-6 relative">
              {/* Creation */}
              <div className="flex items-start">
                <div className="h-5 w-5 rounded-full bg-indigo-500 z-10 mt-1 mr-4"></div>
                <div>
                  <h4 className="text-sm font-medium text-indigo-800">Scan Created</h4>
                  <p className="text-xs text-indigo-500">
                    {scan.created_at && formatToIST(scan.created_at)}
                  </p>
                </div>
              </div>
              {/* Started */}
              <div className="flex items-start">
                <div className={`h-5 w-5 rounded-full z-10 mt-1 mr-4 ${(scan.started_at || scan.summary?.scan_started_at) ? 'bg-indigo-500' : 'bg-indigo-200'}`}></div>
                <div>
                  <h4 className="text-sm font-medium text-indigo-800">Scan Started</h4>
                  <p className="text-xs text-indigo-500">
                    {scan.summary?.scan_started_at 
                      ? formatToIST(scan.summary.scan_started_at) 
                      : scan.started_at 
                        ? formatToIST(scan.started_at) 
                        : 'Pending'
                    }
                  </p>
                </div>
              </div>
              {/* Completed */}
              <div className="flex items-start">
                <div className={`h-5 w-5 rounded-full z-10 mt-1 mr-4 ${
                  (scan.completed_at || scan.summary?.scan_completed_at)
                    ? 'bg-green-500' 
                    : scan.status === 'failed' || scan.summary?.scan_status === 'failed'
                    ? 'bg-red-500'
                    : 'bg-indigo-200'
                }`}></div>
                <div>
                  <h4 className="text-sm font-medium text-indigo-800">
                    {(scan.status === 'failed' || scan.summary?.scan_status === 'failed') ? 'Scan Failed' : 'Scan Completed'}
                  </h4>
                  <p className="text-xs text-indigo-500">
                    {scan.summary?.scan_completed_at 
                      ? formatToIST(scan.summary.scan_completed_at)
                      : scan.completed_at 
                        ? formatToIST(scan.completed_at) 
                        : (scan.status === 'failed' || scan.summary?.scan_status === 'failed')
                          ? 'Error occurred' 
                          : 'Pending'
                    }
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Website URLs section - show this if we have website URL data */}
      {scan.summary && (
        <div className="bg-gradient-to-br from-white/90 to-indigo-50/90 rounded-xl border border-indigo-200/70 p-5 shadow-sm">
          <h3 className="text-lg font-medium text-indigo-800 mb-4 flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Scan Results Overview
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div className="bg-white/70 rounded-lg p-4 border border-indigo-100">
              <div className="text-sm font-medium text-indigo-700 mb-2">Status</div>
              <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                scan.summary.scan_status === 'completed'
                  ? 'bg-green-50 text-green-700 border border-green-200'
                  : scan.summary.scan_status === 'running'
                  ? 'bg-blue-50 text-blue-700 border border-blue-200'
                  : scan.summary.scan_status === 'failed'
                  ? 'bg-red-50 text-red-700 border border-red-200'
                  : 'bg-yellow-50 text-yellow-700 border border-yellow-200'
              }`}>
                {scan.summary.scan_status.charAt(0).toUpperCase() + scan.summary.scan_status.slice(1)}
              </div>
            </div>
            
            <div className="bg-white/70 rounded-lg p-4 border border-indigo-100">
              <div className="text-sm font-medium text-indigo-700 mb-2">Severity Distribution</div>
              {totalCount > 0 ? (
                <div className="flex items-center gap-1 h-4 w-full bg-gray-200 rounded-full overflow-hidden">
                  {highCount > 0 && (
                    <div 
                      className="h-full bg-red-500" 
                      style={{ width: `${(highCount / totalCount) * 100}%` }}
                      title={`${highCount} High Severity Issues`}
                    ></div>
                  )}
                  {mediumCount > 0 && (
                    <div 
                      className="h-full bg-amber-500" 
                      style={{ width: `${(mediumCount / totalCount) * 100}%` }}
                      title={`${mediumCount} Medium Severity Issues`}
                    ></div>
                  )}
                  {lowCount > 0 && (
                    <div 
                      className="h-full bg-blue-500" 
                      style={{ width: `${(lowCount / totalCount) * 100}%` }}
                      title={`${lowCount} Low Severity Issues`}
                    ></div>
                  )}
                </div>
              ) : (
                <p className="text-sm text-indigo-600">No issues found</p>
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* Top Vulnerabilities */}
      {vulnerabilities.length > 0 && (
        <div className="bg-gradient-to-br from-white/90 to-indigo-50/90 rounded-xl border border-indigo-200/70 p-5 shadow-sm overflow-x-auto">
          <h3 className="text-lg font-medium text-indigo-800 mb-4 flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Top Vulnerabilities
          </h3>
          <div className="space-y-3 min-w-[250px]">
            {vulnerabilities.slice(0, 3).map((vuln, index) => (
              <div key={index} className="bg-white/70 rounded-lg p-4 border border-indigo-100">
                <div className="flex flex-col sm:flex-row justify-between items-start gap-2">
                  <div className="flex items-start gap-3">
                    <span className={`px-3 py-1 rounded-full text-xs border ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity.toUpperCase()}
                    </span>
                    <div>
                      <h4 className="font-medium text-indigo-900">{vuln.type}</h4>
                      <p className="text-sm text-indigo-700">{vuln.description}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
            {vulnerabilities.length > 3 && (
              <button 
                onClick={onViewAllVulnerabilities}
                className="text-sm text-indigo-600 hover:text-indigo-800 font-medium"
              >
                View All Vulnerabilities ({vulnerabilities.length})
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default OverviewTab;