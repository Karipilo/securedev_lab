// Pipeline CI/CD DevSecOps - SecureDev Tickets (OCY1102 EV3)
pipeline {
    agent any

    triggers {
        // Revisión continua: Jenkins consulta GitHub cada ~5 minutos y
        // ejecuta el pipeline cuando hay commits nuevos.
        pollSCM('H/5 * * * *')
    }

    options {
        timestamps()
        // Evita builds simultáneos que compartan reportes (integridad de evidencias).
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        APP_URL = 'http://securedev-app:8000'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh '''
                    # Se eliminan reportes de builds anteriores para que la evidencia
                    # archivada corresponda siempre a este build.
                    rm -rf reports && mkdir -p reports
                    git log -1 --pretty="commit=%H%nautor=%an%nfecha=%ci%nmensaje=%s" | tee reports/trazabilidad.txt
                    echo "build=${BUILD_NUMBER}" >> reports/trazabilidad.txt
                '''
            }
        }

        stage('Preparar entorno') {
            steps {
                sh '''
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install -q --upgrade pip
                    pip install -q -r requirements.txt -r requirements-dev.txt
                '''
            }
        }

        stage('Dependencias - pip-audit (SCA)') {
            steps {
                // Política de riesgo: no se despliega si alguna dependencia
                // tiene vulnerabilidades conocidas (CVE/PYSEC) con parche disponible.
                sh '''
                    . .venv/bin/activate
                    pip freeze > reports/dependencias-instaladas.txt
                    # Se auditan las dependencias de producción y de desarrollo.
                    pip-audit -r requirements.txt -r requirements-dev.txt -f json -o reports/pip-audit.json || true
                    if pip-audit -r requirements.txt -r requirements-dev.txt --desc -f markdown -o reports/pip-audit.md; then
                        RESULTADO=0
                        echo "Sin vulnerabilidades conocidas en requirements.txt y requirements-dev.txt (build ${BUILD_NUMBER})." > reports/pip-audit.md
                    else
                        RESULTADO=1
                    fi
                    cat reports/pip-audit.md
                    if [ "$RESULTADO" -ne 0 ]; then
                        echo "POLÍTICA DE DEPENDENCIAS: se encontraron vulnerabilidades conocidas. Se bloquea el despliegue."
                        exit 1
                    fi
                    echo "Dependencias sin vulnerabilidades conocidas."
                '''
            }
        }

        stage('SAST - Bandit') {
            steps {
                sh '''
                    . .venv/bin/activate
                    bandit -r app.py -f html -o reports/bandit.html || true
                    bandit -r app.py -f txt  -o reports/bandit.txt  || true
                    cat reports/bandit.txt
                '''
            }
        }

        stage('Pruebas') {
            steps {
                sh '''
                    . .venv/bin/activate
                    python -m pytest -v --junitxml=reports/junit.xml tests/
                '''
            }
        }

        stage('Build') {
            steps {
                sh 'docker build -t securedev-app:${BUILD_NUMBER} -t securedev-app:latest .'
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    docker compose up -d --no-build --force-recreate
                    for i in $(seq 1 20); do
                        curl -fsS ${APP_URL}/health && exit 0
                        sleep 2
                    done
                    echo "La aplicación no respondió al health check" && exit 1
                '''
            }
        }
    }

    post {
        always {
            junit allowEmptyResults: true, testResults: 'reports/junit.xml'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            publishHTML(target: [reportName: 'Bandit (SAST)', reportDir: 'reports',
                                 reportFiles: 'bandit.html', keepAll: true,
                                 alwaysLinkToLastBuild: true, allowMissing: true])
        }
    }
}
