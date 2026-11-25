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
        stage('DAST - OWASP ZAP') {
            options {
                timeout(time: 25, unit: 'MINUTES')
            }
            steps {
                // Escaneo dinámico autenticado contra la aplicación desplegada.
                // El plan está en security/zap-plan.yaml (spider + pasivo + activo).
                sh '''
                    ZAP="zap-${BUILD_NUMBER}"
                    docker rm -f "$ZAP" >/dev/null 2>&1 || true
                    docker pull -q zaproxy/zap-stable
                    docker create --name "$ZAP" --network devsecops zaproxy/zap-stable \
                        zap.sh -cmd -autorun /home/zap/zap-plan.yaml
                    docker cp security/zap-plan.yaml "$ZAP":/home/zap/zap-plan.yaml
                    docker start -a "$ZAP" && CODIGO=0 || CODIGO=$?
                    echo "ZAP finalizó con código $CODIGO"
                    mkdir -p reports/zap
                    # Se guarda siempre el log interno de ZAP como evidencia.
                    docker cp "$ZAP":/home/zap/.ZAP/zap.log reports/zap/zap.log || true
                    for f in zap-report.html zap-report.json zap-report.md; do
                        docker cp "$ZAP":/home/zap/$f reports/zap/ || true
                    done
                    docker rm -f "$ZAP"
                    if [ ! -f reports/zap/zap-report.json ]; then
                        echo "ZAP no generó reportes. Últimas líneas de su log:"
                        tail -n 40 reports/zap/zap.log || true
                        exit 1
                    fi
                '''
                script {
                    // Política DAST: alertas de riesgo ALTO marcan el build como
                    // inestable (amarillo) para exigir su corrección.
                    def altos = sh(returnStdout: true,
                        script: 'python3 security/zap_resumen.py reports/zap/zap-report.json reports/zap/resumen.txt').trim()
                    if (altos.toInteger() > 0) {
                        unstable("POLÍTICA DAST: OWASP ZAP encontró ${altos} alerta(s) de riesgo ALTO")
                    }
                }
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
            publishHTML(target: [reportName: 'OWASP ZAP (DAST)', reportDir: 'reports/zap',
                                 reportFiles: 'zap-report.html', keepAll: true,
                                 alwaysLinkToLastBuild: true, allowMissing: true])
        }
    }
}
