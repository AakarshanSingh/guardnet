import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import { Toaster } from "react-hot-toast"; // Import the Toaster component
import FormComponent from "./components/FormComponent";
import LandingPage from "./components/LandingPage";

const App = () => {
  return (
    <Router>
      <Toaster /> {/* Place the Toaster here, at the root level */}
      
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/check" element={<FormComponent />} />
      </Routes>
    </Router>
  );
};

export default App;
