pipeline {
    agent any // Or a specific agent like 'agent { label 'your-agent-label' }'

    environment {
        // Ensure your API_KEY is securely stored in Jenkins Credentials and accessed here
        // For example, if you have a 'Secret text' credential named 'GEMINI_API_KEY_CRED'
        GEMINI_API_KEY = credentials('GEMINI_API_KEY_CRED') 
        REPORT_FILENAME = "gemini_security_report.html"
        JSON_OUTPUT_FILENAME = "gemini_security_findings.json"
        // Define the path to your Python script relative to the workspace root
        SCANNER_SCRIPT = "ai_scanner.py" 
        // Define the folder to scan. Use '.' for the entire repository.
        CODE_TO_SCAN_PATH = "." 
    }

    stages {
        stage('Checkout Code') {
            steps {
                // Adjust this based on your SCM (e.g., Git, SVN)
                git branch: 'main', url: 'YOUR_REPOSITORY_URL' 
            }
        }

        stage('Setup Python Environment') {
            steps {
                script {
                    // Use a virtual environment for better dependency management
                    sh 'python3 -m venv venv'
                    sh '. venv/bin/activate && pip install -r requirements.txt' 
                    // Create a requirements.txt if you don't have one:
                    // echo "google-generativeai" > requirements.txt
                    // echo "os" >> requirements.txt
                    // echo "sys" >> requirements.txt
                    // echo "argparse" >> requirements.txt
                    // echo "re" >> requirements.txt
                    // echo "html" >> requirements.txt
                    // echo "datetime" >> requirements.txt
                    // echo "json" >> requirements.txt
                }
            }
        }

        stage('Run AI Security Scan') {
            steps {
                script {
                    // Ensure the virtual environment is activated before running the script
                    sh ". venv/bin/activate && python3 ${SCANNER_SCRIPT} ${CODE_TO_SCAN_PATH} -o ${REPORT_FILENAME} --json-output ${JSON_OUTPUT_FILENAME}"
                }
            }
        }

        stage('Publish Report') {
            steps {
                // Archive the generated HTML report for easy access
                archiveArtifacts artifacts: REPORT_FILENAME, fingerprint: true
                
                // You can also publish the JSON results if needed
                archiveArtifacts artifacts: JSON_OUTPUT_FILENAME, fingerprint: true

                // Use the HTML Publisher Plugin to display the report in Jenkins
                // Ensure you have the 'HTML Publisher Plugin' installed in Jenkins
                publishHTML (
                    target: [
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.', // The directory where the report is located
                        reportFiles: REPORT_FILENAME, // The main HTML report file
                        reportName: 'AI Security Scan Report'
                    ]
                )
            }
        }
    }

    post {
        always {
            cleanWs() // Clean up the workspace after the build
        }
        failure {
            echo 'AI Security Scan failed. Check logs for details.'
            // Add notifications here, e.g., email, Slack
        }
        success {
            echo 'AI Security Scan completed successfully.'
        }
    }
}