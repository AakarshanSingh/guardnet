import { createContext, useState, ReactNode, useContext } from 'react';
import axios from 'axios';
import { toast } from 'react-hot-toast';
import { AuthContext } from './AuthContext';

// Helper function to convert timestamps to local time zone
export const formatToIST = (timestamp: string | undefined): string => {
  if (!timestamp) return 'N/A';
  
  const options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  };
  
  return new Date(timestamp).toLocaleString(undefined, options);
};

// Define types
export interface Website {
  id: string;
  url: string;
  cookies?: string;
  user_id: string;
  created_at: string;
}

export interface Scan {
  id: string;
  website_id: string;
  website?: Website;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  created_at: string;
}

export interface ScanResult {
  id: string;
  scan_id: string;
  scan_type: string;
  result_data: any;
  created_at: string;
}

interface ScanContextType {
  scans: Scan[];
  results: Record<string, ScanResult[]>;
  loading: boolean;
  submitScan: (url: string, cookies?: string) => Promise<string | null>;
  getScanStatus: (scanId: string) => Promise<string>;
  getScanResults: (scanId: string) => Promise<ScanResult[] | null>;
  fetchUserScans: (page?: number, limit?: number) => Promise<Scan[]>;
  downloadReport: (
    scanId: string,
    format: 'pdf' | 'excel' | 'json'
  ) => Promise<boolean>;
}

// Create context with default values
const initialScanContext: ScanContextType = {
  scans: [],
  results: {},
  loading: false,
  submitScan: async () => null,
  getScanStatus: async () => '',
  getScanResults: async () => null,
  fetchUserScans: async () => [],
  downloadReport: async () => false,
};

// Export the context
export const ScanContext = createContext<ScanContextType>(initialScanContext);

// Create custom hook for accessing the context
export const useScanContext = () => useContext(ScanContext);

// Export the provider as a named export first
const ScanProvider = ({ children }: { children: ReactNode }) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [results, setResults] = useState<Record<string, ScanResult[]>>({});
  const [loading, setLoading] = useState<boolean>(false);
  const { isAuthenticated } = useContext(AuthContext);

  // Submit a new scan
  const submitScan = async (
    url: string,
    cookies?: string
  ): Promise<string | null> => {
    if (!isAuthenticated) {
      toast.error('Please login to submit a scan');
      return null;
    }

    try {
      setLoading(true);

      const response = await axios.post('/api/scan', {
        url,
        cookies,
      });

      if (
        response.data &&
        response.data.success &&
        response.data.data?.scan_id
      ) {
        toast.success(response.data.message || 'Scan submitted successfully');
        fetchUserScans();
        return response.data.data.scan_id;
      } else {
        toast.error(response.data.message || 'Failed to submit scan');
        return null;
      }
    } catch (error: any) {
      const errorMessage =
        error.response?.data?.message || 'Failed to submit scan';
      toast.error(errorMessage);
      console.error('Scan submission error:', error);
      return null;
    } finally {
      setLoading(false);
    }
  };

  // Get scan status
  const getScanStatus = async (scanId: string): Promise<string> => {
    try {
      const response = await axios.get(`/api/scan/status?id=${scanId}`);

      if (response.data.status) {
        // Find the scan and update its status if scans array exists
        if (scans && scans.length > 0) {
          const updatedScans = scans.map((scan) =>
            scan.id === scanId
              ? { ...scan, status: response.data.status }
              : scan
          );

          setScans(updatedScans);
        }
        return response.data.status;
      }

      return '';
    } catch (error) {
      console.error('Get scan status error:', error);
      return '';
    }
  };

  // Get scan results
  const getScanResults = async (
    scanId: string
  ): Promise<ScanResult[] | null> => {
    try {
      const response = await axios.get(`/api/scan/result?id=${scanId}`);
      console.log(response.data);
      if (response.data && response.data.success) {
        // Handle new response format with data property containing scan results
        const scanData = response.data.data;
        console.log(scanData);

        // Transform the response data into ScanResult format
        const transformedResults: ScanResult[] = [];

        // Extract scan and website info
        const scanInfo = scanData.scan;
        
        // Store website data if available
        if (scanData.website_data) {
          transformedResults.push({
            id: `website-data-${scanId}`,
            scan_id: scanId,
            scan_type: 'website_data',
            result_data: scanData.website_data,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Store summary information if available
        if (scanData.summary) {
          transformedResults.push({
            id: `summary-${scanId}`,
            scan_id: scanId,
            scan_type: 'summary',
            result_data: scanData.summary,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process WordPress scan data if available
        if (scanData.wordpress) {
          transformedResults.push({
            id: `wp-${scanId}`,
            scan_id: scanId,
            scan_type: 'wordpress',
            result_data: scanData.wordpress,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process DNS data if available
        if (scanData.dns) {
          transformedResults.push({
            id: `dns-${scanId}`,
            scan_id: scanId,
            scan_type: 'dns',
            result_data: scanData.dns,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process ports data if available
        if (scanData.ports) {
          transformedResults.push({
            id: `ports-${scanId}`,
            scan_id: scanId,
            scan_type: 'ports',
            result_data: scanData.ports,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process directories data if available
        if (scanData.directories) {
          transformedResults.push({
            id: `dir-${scanId}`,
            scan_id: scanId,
            scan_type: 'directories',
            result_data: scanData.directories,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process LFI data if available
        if (scanData.lfi) {
          transformedResults.push({
            id: `lfi-${scanId}`,
            scan_id: scanId,
            scan_type: 'lfi',
            result_data: scanData.lfi,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process zone transfer data if available
        if (scanData.zone_transfer) {
          transformedResults.push({
            id: `zone-${scanId}`,
            scan_id: scanId,
            scan_type: 'zone_transfer',
            result_data: scanData.zone_transfer,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process XSS data if available
        if (scanData.xss) {
          transformedResults.push({
            id: `xss-${scanId}`,
            scan_id: scanId,
            scan_type: 'xss',
            result_data: scanData.xss,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process SQL injection data if available
        if (scanData.sqli) {
          transformedResults.push({
            id: `sqli-${scanId}`,
            scan_id: scanId,
            scan_type: 'sqli',
            result_data: scanData.sqli,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Process SSL data if available
        if (scanData.ssl) {
          transformedResults.push({
            id: `ssl-${scanId}`,
            scan_id: scanId,
            scan_type: 'ssl',
            result_data: scanData.ssl,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }
        
        // Process Command Injection data if available
        if (scanData.command_injection) {
          transformedResults.push({
            id: `cmd-${scanId}`,
            scan_id: scanId,
            scan_type: 'command_injection',
            result_data: scanData.command_injection,
            created_at: scanInfo?.created_at || new Date().toISOString(),
          });
        }

        // Store results in state
        setResults((prev) => ({
          ...prev,
          [scanId]: transformedResults,
        }));

        return transformedResults;
      } else if (response.data && response.data.results) {
        // Handle legacy response format with results array
        console.log(
          'Received legacy scan results:',
          response.data.results.length
        );

        setResults((prev) => ({
          ...prev,
          [scanId]: response.data.results,
        }));

        return response.data.results;
      } else {
        console.log('No results found for scan ID:', scanId);
        return null;
      }
    } catch (error) {
      console.error('Get scan results error:', error);
      // If there's an error from the API, make sure the UI can handle it gracefully
      return null;
    }
  };

  // Fetch user scans with pagination
  const fetchUserScans = async (page = 1, limit = 10): Promise<Scan[]> => {
    if (!isAuthenticated) {
      return [];
    }

    try {
      setLoading(true);

      const response = await axios.get(
        `/api/dashboard/scans?page=${page}&limit=${limit}`
      );

      if (response.data && response.data.success && response.data.data) {
        // Extract items from the data structure
        const scanItems = response.data.data.items || [];

        // Map API response items to Scan interface format
        const formattedScans = scanItems.map((item: any) => ({
          id: item.id, // Use ID directly as string/UUID
          website_id: item.website_id,
          website: {
            id: item.website_id,
            url: item.url,
            user_id: item.user_id || '0', // Ensure it's a string
            created_at: item.created_at,
          },
          status: item.status,
          started_at: item.started_at,
          completed_at: item.completed_at,
          created_at: item.created_at,
          // Store vulnerabilities summary for potential use
          vulnerabilities_summary: item.vulnerabilities_summary,
        }));

        // Update state with formatted scans
        setScans(formattedScans);

        // Also update total pages for pagination
        const paginationInfo = response.data.data;
        if (paginationInfo.pages) {
          // This event can be handled in components that need pagination info
          window.dispatchEvent(
            new CustomEvent('pagination:update', {
              detail: {
                totalPages: paginationInfo.pages,
                currentPage: paginationInfo.page,
                totalItems: paginationInfo.total,
              },
            })
          );
        }

        return formattedScans;
      }

      return [];
    } catch (error) {
      console.error('Fetch user scans error:', error);
      return [];
    } finally {
      setLoading(false);
    }
  };

  // Download scan report
  const downloadReport = async (
    scanId: string,
    format: 'pdf' | 'excel' | 'json' = 'pdf'
  ): Promise<boolean> => {
    try {
      const response = await axios.get(
        `/api/scan/report?id=${scanId}&format=${format}`,
        {
          responseType: format === 'json' ? 'json' : 'blob',
          headers: {
            'Content-Type': 'application/json',
            Accept:
              format === 'pdf'
                ? 'application/pdf'
                : format === 'excel'
                ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                : 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
          withCredentials: true,
        }
      );

      // Handle JSON response
      if (format === 'json') {
        if (response.data && response.data.success) {
          toast.success('Report generated successfully');
          // If needed, handle the JSON data here
          return true;
        } else {
          toast.error(response.data?.message || 'Failed to generate report');
          return false;
        }
      }

      // Handle file download (pdf or excel)
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute(
        'download',
        `scan-report-${scanId}.${format === 'pdf' ? 'pdf' : 'xlsx'}`
      );
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      toast.success(`${format.toUpperCase()} report downloaded successfully`);
      return true;
    } catch (error: any) {
      console.error('Download report error:', error);

      // Check specifically for CORS errors
      if (
        (error.message && error.message.includes('NetworkError')) ||
        error.message.includes('Network Error')
      ) {
        toast.error(
          'Network error: CORS policy blocked the request. Please contact the administrator.'
        );
        return false;
      }

      // Extract error message from API response if available
      const errorMessage =
        error.response?.data?.message ||
        (error.response?.status === 404
          ? 'Report not found'
          : error.response?.status === 422
          ? 'Invalid scan ID format'
          : 'Failed to download report');

      toast.error(errorMessage);
      return false;
    }
  };

  return (
    <ScanContext.Provider
      value={{
        scans,
        results,
        loading,
        submitScan,
        getScanStatus,
        getScanResults,
        fetchUserScans,
        downloadReport,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};

export default ScanProvider;
