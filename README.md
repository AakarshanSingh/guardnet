# GuardNet

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.12-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0.0-61DAFB.svg?style=flat&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-latest-646CFF.svg?style=flat&logo=vite)](https://vitejs.dev/)

GuardNet is a comprehensive website vulnerability scanner designed to help identify security issues in web applications. This tool performs multiple security scans to detect common vulnerabilities such as XSS, SQL injection, DNS vulnerabilities, and more.

## ✨ Features

- **Multiple Vulnerability Scanners**:
  - Cross-Site Scripting (XSS) Detection
  - SQL Injection Testing
  - Command Injection Detection
  - Directory Traversal Scanner
  - Local File Inclusion (LFI) Detection
  - SSL/TLS Vulnerability Testing
  - Port Scanner
  - DNS Vulnerability Testing
  - WordPress Vulnerabilities (via WPScan integration)

- **Modern User Interface**:
  - Responsive React frontend
  - Detailed scan reports
  - User-friendly dashboard
  - Animated UI components for enhanced UX

- **Authentication System**:
  - Secure user authentication
  - User-specific scan history
  - Role-based access control

## 🚀 Tech Stack

### Frontend
- React 19
- TypeScript
- Vite
- TailwindCSS
- React Router
- React Hot Toast for notifications

### Backend
- FastAPI
- PostgreSQL
- SQLAlchemy ORM
- Python 3.13+
- JWT Authentication
- Selenium (for dynamic scanning)
- BeautifulSoup4 (for HTML parsing)

## 📋 Prerequisites

- Node.js 18.0+ and npm/yarn
- Python 3.10+
- PostgreSQL database
- (Optional) Docker and Docker Compose for containerized deployment

## 🔧 Installation

### Clone the repository
```bash
git clone https://github.com/AakarshanSingh/guardnet.git
cd guardnet
```

### Backend Setup

#### 1. Navigate to server directory
```bash
cd server
```

#### 2. Create a virtual environment
```bash
python -m venv venv
```

#### 3. Activate the virtual environment
```bash
# On Windows
venv\Scripts\activate

# On Unix or MacOS
source venv/bin/activate
```

#### 4. Install dependencies
```bash
pip install -r requirements.txt
```

#### 5. Create and configure environment variables
```bash
# Create .env file (use .env.example as a template)
cp .env.example .env

# Update the .env file with your database credentials and secret key
# DATABASE_URL=postgresql://username:password@localhost:5432/database
# SECRET_KEY=your_secret_key
# WPSCAN_API_TOKEN=your_wpscan_api_token
```

#### 6. Run the server
```bash
uvicorn main:app --reload
```

### Frontend Setup

#### 1. Navigate to client directory
```bash
cd client
```

#### 2. Install dependencies
```bash
npm install
```

#### 3. Start development server
```bash
npm run dev
```

## 🔍 Usage

1. Access the frontend at `http://localhost:5173`
2. Register for an account or log in
3. Enter a website URL to scan
4. Select the scan types you want to perform
5. Start the scan and view the results in the dashboard

## 📊 Scan Types

- **XSS Scanner**: Detects cross-site scripting vulnerabilities
- **SQL Injection Scanner**: Tests for SQL injection points
- **DNS Scanner**: Checks for DNS misconfigurations and zone transfer vulnerabilities
- **Directory Scanner**: Discovers hidden directories and files
- **LFI Scanner**: Tests for Local File Inclusion vulnerabilities
- **Command Injection Scanner**: Detects OS command injection flaws
- **Port Scanner**: Scans for open ports on the target
- **SSL Scanner**: Checks for SSL/TLS configuration issues
- **WordPress Scanner**: Identifies WordPress-specific vulnerabilities

## 🔒 Security Notes

- This tool should only be used on websites you own or have explicit permission to test
- Unauthorized security testing may be illegal in many jurisdictions
- Always follow responsible disclosure practices if you discover vulnerabilities

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Contact

If you have any questions or feedback, please open an issue in this repository.

## 👥 Contributors

- [@Aakarshan Singh](https://github.com/AakarshanSingh)
- [@Aditya Bansal](https://github.com/Aditya3403)

