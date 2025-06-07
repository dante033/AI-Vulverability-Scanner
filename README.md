# AI Vulnerability Scanner 🛡️

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Version](https://img.shields.io/badge/version-1.0.0-green.svg) ![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

Welcome to the **AI Vulnerability Scanner** repository! This project harnesses the power of artificial intelligence to enhance security by identifying vulnerabilities in network services. 

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Overview

The AI Vulnerability Scanner is an AI-driven tool that leverages Nmap to scan for open services on user-supplied IP addresses. It intelligently matches each service with relevant Common Vulnerabilities and Exposures (CVEs) using SBERT embeddings. Additionally, it classifies the severity of each vulnerability and generates tailored remediation steps through a fine-tuned T5 model. 

This tool is designed for security professionals, system administrators, and anyone interested in improving their network security posture.

## Features

- **Nmap Integration**: Utilizes Nmap to discover open services.
- **AI Matching**: Matches services to CVEs using SBERT embeddings.
- **Severity Classification**: Classifies vulnerabilities based on severity.
- **Tailored Remediation**: Provides customized remediation steps.
- **User-Friendly Interface**: Simple command-line interface for ease of use.

## Installation

To get started with the AI Vulnerability Scanner, follow these steps:

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/dante033/AI-Vulverability-Scanner.git
   ```

2. **Navigate to the Directory**:

   ```bash
   cd AI-Vulverability-Scanner
   ```

3. **Install Dependencies**:

   Make sure you have Python 3.6 or higher installed. Then, run:

   ```bash
   pip install -r requirements.txt
   ```

4. **Download the Latest Release**:

   Visit the [Releases section](https://github.com/dante033/AI-Vulverability-Scanner/releases) to download the latest version. Follow the instructions in the release notes to execute the scanner.

## Usage

Once installed, you can use the scanner from the command line. Here’s a basic example of how to run it:

```bash
python scanner.py --ip <target_ip>
```

Replace `<target_ip>` with the IP address you want to scan.

### Command Line Options

- `--ip`: Specify the target IP address.
- `--output`: Specify the output file for the scan results.
- `--verbose`: Enable verbose logging for detailed output.

## How It Works

### Step 1: Service Discovery with Nmap

The scanner begins by using Nmap to identify open services on the provided IP address. Nmap is a powerful tool for network discovery and security auditing. 

### Step 2: CVE Matching with SBERT

After discovering services, the scanner uses SBERT embeddings to match each service to relevant CVEs. This process involves natural language processing to understand the context and relationships between services and vulnerabilities.

### Step 3: Severity Classification

Each matched CVE is classified based on its severity. This classification helps prioritize which vulnerabilities need immediate attention.

### Step 4: Tailored Remediation Steps

Finally, the scanner generates customized remediation steps using a fine-tuned T5 model. These steps guide users on how to mitigate the identified vulnerabilities effectively.

## Contributing

We welcome contributions to the AI Vulnerability Scanner! If you have suggestions or improvements, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes.
4. Push to your branch.
5. Create a pull request.

Please ensure your code follows the existing style and includes tests where applicable.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback, feel free to reach out:

- **Email**: your.email@example.com
- **GitHub**: [dante033](https://github.com/dante033)

Thank you for your interest in the AI Vulnerability Scanner! We hope this tool helps you enhance your network security. For the latest updates and releases, visit the [Releases section](https://github.com/dante033/AI-Vulverability-Scanner/releases).