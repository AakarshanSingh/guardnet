import React from 'react';

interface DNSRecord {
  [key: string]: any[];
}

interface DNSMisconfiguration {
  severity: string;
  title: string;
  description: string;
}

interface DNSData {
  records?: DNSRecord;
  misconfigurations?: DNSMisconfiguration[];
}

interface DNSInformationProps {
  dnsData: DNSData | null;
}

const DNSInformation: React.FC<DNSInformationProps> = ({ dnsData }) => {
  if (!dnsData) {
    return <p className="text-indigo-600">No DNS information available.</p>;
  }

  const hasRecords = dnsData.records && Object.keys(dnsData.records).some(key => 
    dnsData.records![key]?.length > 0
  );

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* DNS Records */}
      <div>
        <h4 className="text-md font-medium text-indigo-700 mb-2">DNS Records</h4>
        {hasRecords ? (
          <div className="space-y-3">
            {Object.entries(dnsData.records || {}).map(([recordType, records]) => {
              if (!records || records.length === 0) return null;
              return (
                <div key={recordType} className="bg-indigo-50/50 rounded-lg p-2 border border-indigo-100">
                  <h5 className="text-sm font-medium text-indigo-800">{recordType}</h5>
                  <div className="mt-1 space-y-1">
                    {records.map((record: any, idx: number) => (
                      <p key={idx} className="text-xs text-indigo-700">
                        {typeof record === 'string' ? record : JSON.stringify(record)}
                      </p>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-sm text-indigo-600">No DNS records found.</p>
        )}
      </div>
      
      {/* DNS Misconfigurations */}
      <div>
        <h4 className="text-md font-medium text-indigo-700 mb-2">DNS Misconfigurations</h4>
        {dnsData.misconfigurations && dnsData.misconfigurations.length > 0 ? (
          <div className="space-y-3">
            {dnsData.misconfigurations.map((issue: DNSMisconfiguration, idx: number) => (
              <div key={idx} className={`rounded-lg p-3 border ${
                issue.severity === 'high' ? 'bg-red-50 border-red-200 text-red-700' :
                issue.severity === 'medium' ? 'bg-amber-50 border-amber-200 text-amber-700' :
                'bg-blue-50 border-blue-200 text-blue-700'
              }`}>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 text-xs rounded-full border ${
                    issue.severity === 'high' ? 'border-red-300 bg-red-100' :
                    issue.severity === 'medium' ? 'border-amber-300 bg-amber-100' :
                    'border-blue-300 bg-blue-100'
                  }`}>
                    {issue.severity.toUpperCase()}
                  </span>
                  <h5 className="text-sm font-medium">{issue.title}</h5>
                </div>
                <p className="mt-1 text-xs">{issue.description}</p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-indigo-600">No DNS misconfigurations detected.</p>
        )}
      </div>
    </div>
  );
};

export default DNSInformation;