import React, { useState, useContext, useRef, useEffect } from 'react';
import { AuthContext } from '../../context/AuthContext';
import { useNavigate } from 'react-router';
import PasswordChangeModal from './PasswordChangeModal';

const UserMenu: React.FC = () => {
  const { user, logout } = useContext(AuthContext);
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [showPasswordModal, setShowPasswordModal] = useState<boolean>(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Close dropdown when clicking outside
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <>
      <div className='relative' ref={dropdownRef}>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className='flex items-center gap-2 px-2 py-1 rounded-lg hover:bg-indigo-50 transition-all duration-300 cursor-pointer group'
        >
          <div className='h-8 w-8 rounded-full bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center text-white font-medium shadow-sm group-hover:shadow-md transition-all duration-300'>
            {user?.name?.charAt(0).toUpperCase() || 'U'}
          </div>
          <span className='text-indigo-700 max-w-[100px] truncate hidden sm:block'>
            {user?.name}
          </span>
          <svg
            xmlns='http://www.w3.org/2000/svg'
            className={`h-4 w-4 text-indigo-600 transition-transform duration-300 ease-in-out hidden sm:block ${
              isOpen ? 'rotate-180' : ''
            }`}
            fill='none'
            viewBox='0 0 24 24'
            stroke='currentColor'
          >
            <path
              strokeLinecap='round'
              strokeLinejoin='round'
              strokeWidth={2}
              d='M19 9l-7 7-7-7'
            />
          </svg>
        </button>

        {/* Dropdown Menu */}
        {isOpen && (
          <div className='absolute right-0 mt-2 w-56 py-2 bg-white rounded-lg shadow-lg border border-indigo-100 z-10 transition-all duration-200 animate-fadeIn'>
            <div className='px-4 py-2 border-b border-indigo-100'>
              <p className='text-sm font-medium text-indigo-900'>
                {user?.name}
              </p>
              <p className='text-xs text-indigo-600 truncate'>{user?.email}</p>
            </div>
            <button
              onClick={() => {
                setShowPasswordModal(true);
                setIsOpen(false);
              }}
              className='flex items-center w-full px-4 py-2 text-left text-sm text-indigo-700 hover:bg-indigo-50 transition-colors duration-200 cursor-pointer group'
            >
              <svg
                xmlns='http://www.w3.org/2000/svg'
                className='h-4 w-4 mr-2 text-indigo-500 group-hover:text-indigo-700 transition-colors duration-200'
                fill='none'
                viewBox='0 0 24 24'
                stroke='currentColor'
              >
                <path
                  strokeLinecap='round'
                  strokeLinejoin='round'
                  strokeWidth={2}
                  d='M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z'
                />
              </svg>
              Change Password
            </button>
            <button
              onClick={handleLogout}
              className='flex items-center w-full px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50 transition-colors duration-200 cursor-pointer group'
            >
              <svg
                xmlns='http://www.w3.org/2000/svg'
                className='h-4 w-4 mr-2 text-red-500 group-hover:text-red-700 transition-colors duration-200'
                fill='none'
                viewBox='0 0 24 24'
                stroke='currentColor'
              >
                <path
                  strokeLinecap='round'
                  strokeLinejoin='round'
                  strokeWidth={2}
                  d='M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1'
                />
              </svg>
              Sign Out
            </button>
          </div>
        )}
      </div>

      <PasswordChangeModal
        isOpen={showPasswordModal}
        onClose={() => setShowPasswordModal(false)}
      />
    </>
  );
};

export default UserMenu;
