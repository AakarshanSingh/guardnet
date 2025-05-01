import { useNavigate } from 'react-router';
import { Scan } from '../../context/ScanContext';
import { formatDistanceToNow } from 'date-fns';

interface ScanCardProps {
  scan: Scan;
}

const ScanCard: React.FC<ScanCardProps> = ({ scan }) => {
  const navigate = useNavigate();
  
  const handleCardClick = () => {
    navigate(`/scans/${scan.id}`);
  };
  
  // Get status color
  const getStatusColor = () => {
    switch (scan.status) {
      case 'completed':
        return 'bg-green-50 text-green-700 border-green-200';
      case 'running':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'failed':
        return 'bg-red-50 text-red-700 border-red-200';
      default:
        return 'bg-yellow-50 text-yellow-700 border-yellow-200';
    }
  };
  
  return (
    <div
      onClick={handleCardClick}
      className="backdrop-blur-sm bg-white/80 rounded-xl border border-indigo-100 p-5 shadow-sm hover:shadow-md transition-all duration-300 cursor-pointer transform hover:-translate-y-1"
    >
      <div className="mb-3 flex justify-between items-start">
        <h3 className="font-medium text-indigo-900 break-all line-clamp-1">
          {scan.website?.url || 'URL not available'}
        </h3>
        <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusColor()}`}>
          {scan.status === 'running' && (
            <span className="h-1.5 w-1.5 bg-blue-500 rounded-full animate-pulse mr-1"></span>
          )}
          {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
        </span>
      </div>
      
      <div className="flex items-center text-xs text-indigo-500 mb-4">
        <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
      </div>
      
      <div className="flex flex-wrap gap-2 mb-4">
        <span className="text-xs bg-indigo-50 text-indigo-700 px-2 py-1 rounded-md border border-indigo-100">
          Full Scan
        </span>
      </div>
      
      <div className="mt-4 pt-2 border-t border-indigo-50 flex justify-between items-center">
        <span className="text-xs text-indigo-500">
          {scan.completed_at ? (
            <>Completed {formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true })}</>
          ) : scan.status === 'running' ? (
            <>Scan in progress...</>
          ) : scan.status === 'pending' ? (
            <>Awaiting processing...</>
          ) : (
            <>Scan failed</>
          )}
        </span>
        
        <button
          onClick={(e) => {
            e.stopPropagation();
            navigate(`/scans/${scan.id}`);
          }}
          className="p-1 text-indigo-600 hover:text-indigo-800 rounded-md hover:bg-indigo-50 transition-colors duration-200 cursor-pointer"
          aria-label="View details"
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
        </button>
      </div>
    </div>
  );
};

export default ScanCard;