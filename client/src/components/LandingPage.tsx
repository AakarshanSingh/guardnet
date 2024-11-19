import React from "react";
import { useNavigate } from "react-router-dom";
import "./LandingPage.css";

const LandingPage = () => {
  const navigate = useNavigate();

  const redirectToForm = () => {
    navigate("/check"); // Redirect to /check form page
  };

  return (
    <div className="landing-container">
      <div className="landing-wrapper">
        <div className="landing-header">
          <h1>Welcome to GuardNet</h1>
          <p className="tagline">Test your website for vulnerabilities with ease</p>
        </div>

        <div className="landing-content">
          <p>
            GuardNet performs detailed security tests on your website, identifying vulnerabilities and providing you with actionable insights to improve security.
            Start the scan by submitting your website URL, email, and necessary cookies data. It's fast, easy, and secure.
          </p>
        </div>

        <div className="landing-footer">
          <button onClick={redirectToForm} className="cta-button">
            Start Scanning Now
          </button>
        </div>
      </div>
    </div>
  );
};

export default LandingPage;
