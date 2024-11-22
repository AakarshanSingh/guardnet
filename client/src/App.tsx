import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import FormComponent from './components/FormComponent';
import LandingPage from './components/LandingPage';
import ResultsPage from './components/ResultsPage.tsx';

const App = () => {
  return (
    <Router>
      <Toaster />
      <Routes>
        <Route path='/' element={<LandingPage />} />
        <Route path='/check' element={<FormComponent />} />
        <Route path='/results' element={<ResultsPage />} />
      </Routes>
    </Router>
  );
};

export default App;
