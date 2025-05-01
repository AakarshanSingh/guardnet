import React from 'react';

interface PortData {
  open_ports?: number[];
  services_detected?: Record<string, string>;
}

interface PortInformationProps {
  portData: PortData | null;
}

const PortInformation: React.FC<PortInformationProps> = ({ portData }) => {
  if (!portData || !portData.open_ports || portData.open_ports.length === 0) {
    return (
      <p className="text-indigo-600">No open ports detected.</p>
    );
  }

  return (
    <>
      <h4 className="text-md font-medium text-indigo-700">Open Ports</h4>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {portData.open_ports.map((port: number) => {
          const service = portData.services_detected 
            ? portData.services_detected[port.toString()] 
            : 'Unknown';
          
          return (
            <div key={port} className="flex items-center p-3 bg-indigo-50/50 rounded-lg border border-indigo-100">
              <div className="flex-shrink-0 h-10 w-10 bg-indigo-100 rounded-md flex items-center justify-center text-indigo-600 font-medium">
                {port}
              </div>
              <div className="ml-4">
                <h5 className="text-sm font-medium text-indigo-900">{service}</h5>
                <p className="text-xs text-indigo-500">TCP Service</p>
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-3 p-3 bg-indigo-50/50 rounded-lg border border-indigo-100">
        <p className="text-sm text-indigo-700">
          <span className="font-medium">Security Note:</span> Open ports provide potential entry points for attackers. 
          Consider disabling unnecessary services and implementing proper firewall rules.
        </p>
      </div>
    </>
  );
};

export default PortInformation;