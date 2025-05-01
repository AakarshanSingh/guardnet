import React from 'react';

const Footer: React.FC = () => {
  return (
    <footer className='bg-white/80 mb-auto backdrop-blur-sm border-t border-indigo-100'>
      <div className='container mx-auto px-4 sm:px-6 lg:px-8 py-6'>
        <div className='flex flex-col md:flex-row justify-between items-center'>
          <div className='mb-4 md:mb-0'>
            <div className='flex items-center space-x-2'>
              <div className='h-6 w-6 rounded-lg bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center text-white font-bold text-sm shadow-sm'>
                G
              </div>
              <span className='text-sm font-bold text-indigo-900'>
                GuardNet
              </span>
            </div>
            <p className='text-xs text-indigo-600 mt-1'>
              © {new Date().getFullYear()} GuardNet. All rights reserved.
            </p>
          </div>
          <div className='flex items-center space-x-4'>
            <a
              href='#'
              className='text-sm text-indigo-600 hover:text-indigo-800'
            >
              Privacy Policy
            </a>
            <a
              href='#'
              className='text-sm text-indigo-600 hover:text-indigo-800'
            >
              Terms of Service
            </a>
            <a
              href='#'
              className='text-sm text-indigo-600 hover:text-indigo-800'
            >
              Contact
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;