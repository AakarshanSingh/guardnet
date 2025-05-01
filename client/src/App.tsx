import { BrowserRouter as Router, Route, Routes } from 'react-router';
import { Toaster } from 'react-hot-toast';
import AuthProvider from './context/AuthContext';
import ScanProvider from './context/ScanContext';
import HomePage from './pages/HomePage';
import ScanPage from './pages/ScanPage';
import DashboardPage from './pages/DashboardPage';
import ScanDetailsPage from './pages/ScanDetailsPage';
import './App.css';

function App() {
  return (
    <Router>
      <AuthProvider>
        <ScanProvider>
          {/* Main Content */}
          <Routes>
            <Route path='/' element={<HomePage />} />
            <Route path='/scan' element={<ScanPage />} />
            <Route path='/dashboard' element={<DashboardPage />} />
            <Route path='/scans/:scanId' element={<ScanDetailsPage />} />
          </Routes>

          {/* Toast notifications */}
          <Toaster position='top-center' />
        </ScanProvider>
      </AuthProvider>
    </Router>
  );
}

export default App;
