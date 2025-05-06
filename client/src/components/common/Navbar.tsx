import React, { useState, useContext, useEffect } from 'react';
import { Link, useLocation } from 'react-router';
import { AuthContext } from '../../context/AuthContext';
import UserMenu from '../auth/UserMenu';
import AuthModal from '../auth/AuthModal';

const Navbar: React.FC = () => {
  const { isAuthenticated } = useContext(AuthContext);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const location = useLocation();

  useEffect(() => {
    setIsMenuOpen(false);
  }, [location]);

  useEffect(() => {
    const openLogin = () => {
      setAuthMode('login');
      setShowAuthModal(true);
    };
    const openRegister = () => {
      setAuthMode('register');
      setShowAuthModal(true);
    };
    window.addEventListener('open:login', openLogin);
    window.addEventListener('open:register', openRegister);
    return () => {
      window.removeEventListener('open:login', openLogin);
      window.removeEventListener('open:register', openRegister);
    };
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Element;
      if (
        isMenuOpen &&
        !target.closest('#mobile-menu') &&
        !target.closest('#menu-button')
      ) {
        setIsMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isMenuOpen]);

  useEffect(() => {
    if (isMenuOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'auto';
    }
    return () => {
      document.body.style.overflow = 'auto';
    };
  }, [isMenuOpen]);

  return (
    <>
      <header className='bg-white/80 backdrop-blur-sm shadow-sm border-b border-indigo-100 sticky top-0 z-30 w-full'>
        <div className='container mx-auto px-2 sm:px-4 md:px-6 lg:px-8'>
          <div className='flex justify-between items-center h-16'>
            {/* Logo */}
            <Link to='/' className='flex items-center space-x-2 min-w-[48px]'>
              <div className='h-8 w-8 rounded-lg bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center text-white font-bold text-xl shadow-md'>
                G
              </div>
              <span className='text-xl font-bold text-indigo-900'>
                GuardNet
              </span>
            </Link>

            {/* Mobile menu button */}
            <button
              id='menu-button'
              className='md:hidden p-2 rounded-md text-indigo-700 hover:bg-indigo-100 focus:outline-none transition-colors duration-300 relative overflow-hidden group'
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              aria-label='Toggle menu'
            >
              <span className='absolute inset-0 w-full h-full bg-indigo-50 opacity-0 group-hover:opacity-100 group-active:opacity-70 transition-opacity duration-300 rounded-md'></span>
              <svg
                xmlns='http://www.w3.org/2000/svg'
                className='h-6 w-6 relative z-10 transition-transform duration-300 ease-in-out'
                fill='none'
                viewBox='0 0 24 24'
                stroke='currentColor'
              >
                {isMenuOpen ? (
                  <path
                    strokeLinecap='round'
                    strokeLinejoin='round'
                    strokeWidth={2}
                    d='M6 18L18 6M6 6l12 12'
                  />
                ) : (
                  <path
                    strokeLinecap='round'
                    strokeLinejoin='round'
                    strokeWidth={2}
                    d='M4 6h16M4 12h16M4 18h16'
                  />
                )}
              </svg>
            </button>

            {/* Desktop Navigation */}
            <nav className='hidden md:flex items-center space-x-2 lg:space-x-4'>
              <Link
                to='/'
                className={`px-3 py-2 rounded-md text-sm font-medium text-indigo-700 hover:bg-indigo-100 hover:text-indigo-900 transition-colors duration-200 cursor-pointer ${
                  location.pathname === '/' ? 'bg-indigo-50' : ''
                }`}
              >
                Home
              </Link>
              <Link
                to='/scan'
                className={`px-3 py-2 rounded-md text-sm font-medium text-indigo-700 hover:bg-indigo-100 hover:text-indigo-900 transition-colors duration-200 cursor-pointer ${
                  location.pathname === '/scan' ? 'bg-indigo-50' : ''
                }`}
              >
                Scanner
              </Link>
              <Link
                to='/dashboard'
                className={`px-3 py-2 rounded-md text-sm font-medium text-indigo-700 hover:bg-indigo-100 hover:text-indigo-900 transition-colors duration-200 cursor-pointer ${
                  location.pathname === '/dashboard' ? 'bg-indigo-50' : ''
                }`}
              >
                Dashboard
              </Link>
              {isAuthenticated ? (
                <UserMenu />
              ) : (
                <div className='flex items-center space-x-2'>
                  <button
                    onClick={() => {
                      setAuthMode('login');
                      setShowAuthModal(true);
                    }}
                    className='px-4 py-2 rounded-lg text-sm font-medium text-indigo-700 hover:bg-indigo-100 hover:text-indigo-900 transition-colors duration-200 cursor-pointer'
                  >
                    Sign In
                  </button>
                  <button
                    onClick={() => {
                      setAuthMode('register');
                      setShowAuthModal(true);
                    }}
                    className='px-4 py-2 rounded-lg text-sm font-medium text-white bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 shadow-sm hover:shadow-md transition-all duration-300 cursor-pointer hover:-translate-y-0.5'
                  >
                    Get Started
                  </button>
                </div>
              )}
            </nav>
          </div>
        </div>

        {/* Mobile Menu */}
        {isMenuOpen && (
          <div
            id='mobile-menu'
            className='md:hidden fixed inset-0 z-40 bg-gradient-to-br from-white/95 to-indigo-50/95 backdrop-blur-md animate-fadeIn overflow-y-auto'
            style={{ animation: 'fadeIn 0.3s ease-out forwards' }}
          >
            <div className='pt-20 pb-6 px-4 flex flex-col h-full min-h-screen'>
              <nav className='flex flex-col space-y-4 mb-8'>
                <Link
                  to='/'
                  className={`px-4 py-3 rounded-lg text-center text-lg font-medium transition-all duration-300 ${
                    location.pathname === '/'
                      ? 'bg-indigo-100 text-indigo-800 shadow-sm'
                      : 'text-indigo-700 hover:bg-indigo-50'
                  }`}
                >
                  Home
                </Link>
                <Link
                  to='/scan'
                  className={`px-4 py-3 rounded-lg text-center text-lg font-medium transition-all duration-300 ${
                    location.pathname === '/scan'
                      ? 'bg-indigo-100 text-indigo-800 shadow-sm'
                      : 'text-indigo-700 hover:bg-indigo-50'
                  }`}
                >
                  Scanner
                </Link>
                <Link
                  to='/dashboard'
                  className={`px-4 py-3 rounded-lg text-center text-lg font-medium transition-all duration-300 ${
                    location.pathname === '/dashboard'
                      ? 'bg-indigo-100 text-indigo-800 shadow-sm'
                      : 'text-indigo-700 hover:bg-indigo-50'
                  }`}
                >
                  Dashboard
                </Link>
              </nav>
              {!isAuthenticated && (
                <div className='mt-auto flex flex-col space-y-3'>
                  <button
                    onClick={() => {
                      setIsMenuOpen(false);
                      setAuthMode('login');
                      setShowAuthModal(true);
                    }}
                    className='w-full py-3 px-4 rounded-lg text-indigo-700 border border-indigo-200 bg-indigo-50/80 hover:bg-indigo-100 font-medium transition-all duration-300'
                  >
                    Sign In
                  </button>
                  <button
                    onClick={() => {
                      setIsMenuOpen(false);
                      setAuthMode('register');
                      setShowAuthModal(true);
                    }}
                    className='w-full py-3 px-4 rounded-lg text-white bg-gradient-to-r from-indigo-500 to-blue-600 hover:from-indigo-600 hover:to-blue-700 font-medium shadow-md hover:shadow-lg transition-all duration-300'
                  >
                    Get Started
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </header>
      <AuthModal
        isOpen={showAuthModal}
        onClose={() => setShowAuthModal(false)}
        initialMode={authMode}
      />
    </>
  );
};

export default Navbar;
