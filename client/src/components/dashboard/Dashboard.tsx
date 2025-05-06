import { useEffect, useState, useContext } from 'react';
import { useNavigate } from 'react-router';
import { ScanContext } from '../../context/ScanContext';
import { AuthContext } from '../../context/AuthContext';
import ScanCard from './ScanCard';
import Pagination from '../common/Pagination';

const Dashboard = () => {
  const { isAuthenticated, isLoading: authLoading } = useContext(AuthContext);
  const {
    fetchUserScans,
    scans,
    loading: scanLoading,
  } = useContext(ScanContext);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const scanPerPage = 9;
  const navigate = useNavigate();

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
      return;
    }

    loadScans();

    const handlePaginationUpdate = (event: CustomEvent) => {
      if (event.detail) {
        setTotalPages(event.detail.totalPages || 1);
      }
    };

    window.addEventListener(
      'pagination:update',
      handlePaginationUpdate as EventListener
    );

    return () => {
      window.removeEventListener(
        'pagination:update',
        handlePaginationUpdate as EventListener
      );
    };
  }, [isAuthenticated, authLoading, currentPage]);

  const loadScans = async () => {
    await fetchUserScans(currentPage, scanPerPage);
  };

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await loadScans();
    setIsRefreshing(false);
  };

  const handleStartNewScan = () => {
    navigate('/scan');
  };

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  if (authLoading) {
    return (
      <div className='flex justify-center items-center min-h-[50vh]'>
        <div className='flex flex-col items-center'>
          <svg
            className='animate-spin h-12 w-12 text-indigo-500 mb-3'
            xmlns='http://www.w3.org/2000/svg'
            fill='none'
            viewBox='0 0 24 24'
          >
            <circle
              className='opacity-25'
              cx='12'
              cy='12'
              r='10'
              stroke='currentColor'
              strokeWidth='4'
            ></circle>
            <path
              className='opacity-75'
              fill='currentColor'
              d='M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z'
            ></path>
          </svg>
          <span className='text-indigo-700'>Loading...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className='flex flex-col items-center justify-center min-h-[50vh]'>
        <div className='text-center max-w-md'>
          <svg
            xmlns='http://www.w3.org/2000/svg'
            className='h-16 w-16 mx-auto text-indigo-400 mb-4'
            fill='none'
            viewBox='0 0 24 24'
            stroke='currentColor'
          >
            <path
              strokeLinecap='round'
              strokeLinejoin='round'
              strokeWidth={1.5}
              d='M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z'
            />
          </svg>
          <h2 className='text-2xl font-bold text-indigo-800 mb-2'>
            Authentication Required
          </h2>
          <p className='text-indigo-600 mb-6'>
            Please log in to view your dashboard.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className='min-h-[80vh]'>
      {/* Dashboard Header */}
      <div className='flex flex-col md:flex-row md:items-center md:justify-between mb-8 gap-4'>
        <div>
          <h1 className='text-3xl font-bold text-indigo-900'>
            Your Security Dashboard
          </h1>
          <p className='text-indigo-600 mt-1'>
            Monitor and manage all your website security scans
          </p>
        </div>
        <div className='flex items-center gap-3'>
          <button
            onClick={handleRefresh}
            disabled={isRefreshing || scanLoading}
            className={`py-2 px-4 rounded-lg flex items-center gap-2 ${
              isRefreshing || scanLoading
                ? 'bg-gray-300 text-gray-600 cursor-not-allowed'
                : 'bg-indigo-50 text-indigo-700 border border-indigo-200 hover:bg-indigo-100'
            }`}
          >
            <svg
              className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`}
              xmlns='http://www.w3.org/2000/svg'
              fill='none'
              viewBox='0 0 24 24'
              stroke='currentColor'
            >
              <path
                strokeLinecap='round'
                strokeLinejoin='round'
                strokeWidth={2}
                d='M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15'
              />
            </svg>
            Refresh
          </button>
          <button
            onClick={handleStartNewScan}
            className='py-2 px-4 bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 text-white rounded-lg shadow-md hover:shadow-lg transition-all duration-200 flex items-center gap-2'
          >
            <svg
              xmlns='http://www.w3.org/2000/svg'
              className='h-4 w-4'
              fill='none'
              viewBox='0 0 24 24'
              stroke='currentColor'
            >
              <path
                strokeLinecap='round'
                strokeLinejoin='round'
                strokeWidth={2}
                d='M12 4v16m8-8H4'
              />
            </svg>
            New Scan
          </button>
        </div>
      </div>

      {/* Scans Grid */}
      {scanLoading ? (
        <div className='flex justify-center items-center py-16'>
          <div className='flex flex-col items-center'>
            <svg
              className='animate-spin h-10 w-10 text-indigo-500 mb-3'
              xmlns='http://www.w3.org/2000/svg'
              fill='none'
              viewBox='0 0 24 24'
            >
              <circle
                className='opacity-25'
                cx='12'
                cy='12'
                r='10'
                stroke='currentColor'
                strokeWidth='4'
              ></circle>
              <path
                className='opacity-75'
                fill='currentColor'
                d='M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z'
              ></path>
            </svg>
            <span className='text-indigo-700'>Loading your scans...</span>
          </div>
        </div>
      ) : scans.length > 0 ? (
        <div className='space-y-8'>
          <div className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6'>
            {scans.map((scan) => (
              <ScanCard key={scan.id} scan={scan} />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className='flex justify-center mt-8'>
              <Pagination
                currentPage={currentPage}
                totalPages={totalPages}
                onPageChange={handlePageChange}
              />
            </div>
          )}
        </div>
      ) : (
        <div className='backdrop-blur-sm bg-white/50 border border-indigo-100 rounded-2xl p-16 text-center shadow-md'>
          <div className='h-20 w-20 mx-auto text-indigo-300 mb-6'>
            <svg
              xmlns='http://www.w3.org/2000/svg'
              fill='none'
              viewBox='0 0 24 24'
              stroke='currentColor'
            >
              <path
                strokeLinecap='round'
                strokeLinejoin='round'
                strokeWidth={1.5}
                d='M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z'
              />
            </svg>
          </div>
          <h2 className='text-2xl font-bold text-indigo-800 mb-4'>
            No Scans Yet
          </h2>
          <p className='text-indigo-600 mb-8 max-w-md mx-auto'>
            You haven't run any security scans yet. Start by scanning your first
            website to identify vulnerabilities.
          </p>
          <button
            onClick={handleStartNewScan}
            className='py-3 px-6 bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 text-white rounded-lg shadow-md hover:shadow-lg transition-all duration-200'
          >
            Start Your First Scan
          </button>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
