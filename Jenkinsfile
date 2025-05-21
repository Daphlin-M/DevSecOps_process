pipeline {
    agent any
    
    environment {
        PYTHON_VERSION = '3.9'
        VENV_NAME = 'venv'
    }
    
    stages {
        stage('Setup Environment') {
            steps {
                // Clean workspace
                cleanWs()
                
                // Checkout code
                checkout scm
                
                // Create and activate virtual environment
                bat """
                    python -m venv ${VENV_NAME}
                    ${VENV_NAME}\\Scripts\\activate
                    python -m pip install --upgrade pip
                    pip install google-generativeai
                """
            }
        }
        
        stage('Run Security Scanner') {
            steps {
                // Run the scanner with credentials
                withCredentials([string(credentialsId: 'GEMINI_API_KEY', variable: 'GEMINI_API_KEY')]) {
                    bat """
                        ${VENV_NAME}\\Scripts\\activate
                        python generate_report.py
                    """
                }
            }
        }
        
        stage('Archive Results') {
            steps {
                // Archive the HTML report
                archiveArtifacts artifacts: 'security_report.html', allowEmptyArchive: true
            }
        }
    }
    
    post {
        always {
            // Clean up virtual environment
            bat """
                if exist ${VENV_NAME} (
                    rmdir /s /q ${VENV_NAME}
                )
            """
        }
    }
} 