import React, { ReactNode } from 'react';
import { useLocation } from 'react-router';
import Navbar from './Navbar';
import Footer from './Footer';

interface LayoutProps {
  children: ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation();
  
  // Check if current path is a protected route to apply different styling
  const isProtectedRoute = ['/dashboard', '/scan', '/scans'].some(route => 
    location.pathname.startsWith(route)
  );
  
  return (
    <div className="flex flex-col min-h-screen bg-white">
      <Navbar />
      <main
        className={`flex-grow page-transition relative z-0 ${
          isProtectedRoute
            ? 'bg-gradient-to-br from-blue-50/80 to-indigo-50/80'
            : ''
        }`}
        style={{ minHeight: '1px' }}
      >
        <div
          className={
            isProtectedRoute
              ? 'py-6 px-2 sm:px-4 md:px-6 lg:px-8 max-w-7xl w-full mx-auto'
              : 'w-full'
          }
        >
          {children}
        </div>
      </main>
      <Footer />
    </div>
  );
};

export default Layout;