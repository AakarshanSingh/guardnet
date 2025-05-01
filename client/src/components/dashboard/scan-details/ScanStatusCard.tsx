import React from 'react';
import { formatDistanceToNow } from 'date-fns';
import { formatToIST } from '../../../context/ScanContext';

interface ScanStatusCardProps {
  scan: {
    id: string;
    status: string;
    created_at: string;
    started_at?: string;
    completed_at?: string;
    website?: {
      url?: string;
      cookies?: string;
    };
  };
  isRefreshing: boolean;
  onRefresh: () => void;
  onDownloadReport: (format: 'pdf' | 'excel') => void;
  isDownloading: boolean;
}

const ScanStatusCard: React.FC<ScanStatusCardProps> = ({ 
  scan, 
  isRefreshing, 
  onRefresh, 
  onDownloadReport, 
  isDownloading 
}) => {
  return (
    <div className="backdrop-blur-sm bg-white/80 rounded-xl border border-indigo-100 shadow-md mb-6 overflow-hidden">
      <div className="p-5">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="flex flex-col">
            <span className="text-sm text-indigo-500 mb-1">Status</span>
            <div className="flex items-center">
              <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm ${
                scan.status === 'completed'
                  ? 'bg-green-50 text-green-700 border border-green-200'
                  : scan.status === 'running'
                  ? 'bg-blue-50 text-blue-700 border border-blue-200'
                  : scan.status === 'failed'
                  ? 'bg-red-50 text-red-700 border border-red-200'
                  : 'bg-yellow-50 text-yellow-700 border border-yellow-200'
              }`}>
                {scan.status === 'running' && (
                  <span className="h-2 w-2 bg-blue-500 rounded-full animate-pulse mr-1"></span>
                )}
                {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
              </span>
            </div>
          </div>
          
          <div className="flex flex-col">
            <span className="text-sm text-indigo-500 mb-1">Created</span>
            <span className="text-indigo-800 font-medium">{formatToIST(scan.created_at)}</span>
            <span className="text-xs text-indigo-400">
              {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
            </span>
          </div>
          
          <div className="flex flex-col">
            <span className="text-sm text-indigo-500 mb-1">Website</span>
            <span className="text-indigo-800 font-medium truncate max-w-xs">{scan.website?.url || 'Not available'}</span>
          </div>
        </div>
        
        <div className="flex flex-wrap items-center gap-3 mt-6 justify-end">
          {(scan.status === 'pending' || scan.status === 'running') && (
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className={`py-2 px-4 rounded-lg flex items-center gap-2 ${
                isRefreshing
                  ? 'bg-gray-300 text-gray-600 cursor-not-allowed'
                  : 'bg-blue-50 text-blue-700 border border-blue-200 hover:bg-blue-100'
              }`}
            >
              <svg className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Refresh Status
            </button>
          )}
          
          {scan.status === 'completed' && (
            <button
              onClick={() => onDownloadReport('pdf')}
              disabled={isDownloading}
              className={`py-2 px-4 rounded-lg flex items-center gap-2 ${
                isDownloading
                  ? 'bg-gray-300 text-gray-600 cursor-not-allowed'
                  : 'bg-teal-500 text-white hover:bg-teal-600'
              }`}
            >
              <svg className={`h-4 w-4 ${isDownloading ? 'animate-spin' : ''}`} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                {isDownloading ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10" />
                )}
              </svg>
              {isDownloading ? 'Downloading...' : 'Download Report'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanStatusCard;