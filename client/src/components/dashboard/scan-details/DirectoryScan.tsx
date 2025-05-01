import React from 'react';

interface SensitiveFile {
  url: string;
  path: string;
  status: number;
  content_type: string;
  content_length: number;
}

interface DirectoryData {
  directories_found?: string[];
  sensitive_files_found?: SensitiveFile[];
}

interface DirectoryScanProps {
  directoryData: DirectoryData | null;
}

const DirectoryScan: React.FC<DirectoryScanProps> = ({ directoryData }) => {
  if (!directoryData) {
    return <p className="text-indigo-600">No directory scanning information available.</p>;
  }

  const hasSensitiveFiles = directoryData.sensitive_files_found && directoryData.sensitive_files_found.length > 0;
  const hasDirectories = directoryData.directories_found && directoryData.directories_found.length > 0;

  if (!hasSensitiveFiles && !hasDirectories) {
    return <p className="text-indigo-600">No directory scanning results available.</p>;
  }

  return (
    <>
      {/* Sensitive Files Found */}
      {hasSensitiveFiles && (
        <div className="mb-6">
          <h4 className="text-md font-medium text-indigo-700 mb-2">Sensitive Files Found</h4>
          <div className="space-y-2">
            <div className="overflow-x-auto rounded-lg border border-indigo-100">
              <table className="min-w-full divide-y divide-indigo-100">
                <thead className="bg-indigo-50">
                  <tr>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-indigo-700 tracking-wider">Path</th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-indigo-700 tracking-wider">Status</th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-indigo-700 tracking-wider">Content Type</th>
                    <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-indigo-700 tracking-wider">Size</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-indigo-100">
                  {directoryData.sensitive_files_found.slice(0, 20).map((file, idx) => (
                    <tr key={idx} className={idx % 2 === 0 ? 'bg-white' : 'bg-indigo-50/40'}>
                      <td className="px-4 py-2 text-xs text-indigo-900 font-medium">{file.path}</td>
                      <td className="px-4 py-2 text-xs text-indigo-700">{file.status}</td>
                      <td className="px-4 py-2 text-xs text-indigo-700">{file.content_type}</td>
                      <td className="px-4 py-2 text-xs text-indigo-700">{file.content_length} bytes</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {directoryData.sensitive_files_found.length > 20 && (
              <p className="text-xs text-indigo-500 text-center">
                Showing 20 of {directoryData.sensitive_files_found.length} sensitive files
              </p>
            )}
            <div className="p-3 bg-amber-50/70 rounded-lg border border-amber-100">
              <p className="text-sm text-amber-700">
                <span className="font-medium">Security Warning:</span> These sensitive files may expose configuration data, credentials, or other information that could be used by attackers. Consider restricting access to these files or removing them if not needed.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Directories Found */}
      {hasDirectories && (
        <div>
          <h4 className="text-md font-medium text-indigo-700 mb-2">Discovered Directories</h4>
          <div className="bg-indigo-50/50 rounded-lg p-3 border border-indigo-100">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
              {directoryData.directories_found.map((dir, idx) => (
                <div key={idx} className="text-xs text-indigo-700 bg-white p-2 rounded border border-indigo-100">
                  {dir}
                </div>
              ))}
            </div>
          </div>
          <div className="mt-2 p-3 bg-indigo-50/70 rounded-lg border border-indigo-100">
            <p className="text-sm text-indigo-700">
              <span className="font-medium">Note:</span> These directories were discovered by the scanner. Some may contain sensitive information or provide attack vectors if not properly secured.
            </p>
          </div>
        </div>
      )}
    </>
  );
};

export default DirectoryScan;