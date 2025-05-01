import React from 'react';
import VulnerabilityItem, { Vulnerability } from './VulnerabilityItem';

interface VulnerabilitiesTabProps {
  vulnerabilities: Vulnerability[];
}

const VulnerabilitiesTab: React.FC<VulnerabilitiesTabProps> = ({ vulnerabilities }) => {
  if (vulnerabilities.length === 0) {
    return (
      <div className="bg-white/70 rounded-xl border border-indigo-100 p-8 text-center">
        <svg xmlns="http://www.w3.org/2000/svg" className="h-12 w-12 mx-auto text-green-500 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        <h3 className="text-xl font-medium text-indigo-800 mb-2">No Vulnerabilities Found</h3>
        <p className="text-indigo-600">This website has passed all security scans without any issues.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-xl font-medium text-indigo-800">
          All Vulnerabilities <span className="text-indigo-600">({vulnerabilities.length})</span>
        </h3>
      </div>
      
      <div className="space-y-4">
        {vulnerabilities.map((vulnerability, index) => (
          <VulnerabilityItem key={index} vulnerability={vulnerability} />
        ))}
      </div>
    </div>
  );
};

export default VulnerabilitiesTab;