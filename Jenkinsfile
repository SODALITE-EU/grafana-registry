pipeline {
    agent { label 'docker-slave' }
    environment {
        // CI-CD vars
        docker_registry_ip = credentials('jenkins-docker-registry-ip')
        // When triggered from git tag, $BRANCH_NAME is actually GIT's tag_name
        TAG_SEM_VER_COMPLIANT = """${sh(
                returnStdout: true,
                script: './CI-CD/validate_tag.sh SemVar $BRANCH_NAME'
            )}"""

        TAG_MAJOR_RELEASE = """${sh(
                returnStdout: true,
                script: './CI-CD/validate_tag.sh MajRel $BRANCH_NAME'
            )}"""

        TAG_PRODUCTION = """${sh(
                returnStdout: true,
                script: './CI-CD/validate_tag.sh production $BRANCH_NAME'
            )}"""

        TAG_STAGING = """${sh(
                returnStdout: true,
                script: './CI-CD/validate_tag.sh staging $BRANCH_NAME'
            )}"""
   }
    stages {
        stage ('Pull repo code from github') {
            steps {
                checkout scm
            }
        }
        stage('SonarQube analysis'){
            environment {
              scannerHome = tool 'SonarQubeScanner'
            }
            steps {
                withSonarQubeEnv('SonarCloud') {
                    sh  """ #!/bin/bash
                            ${scannerHome}/bin/sonar-scanner
                        """
                }
            }
        }
        stage('Inspect GIT TAG'){
            steps {
                sh """ #!/bin/bash
                echo 'TAG: $BRANCH_NAME'
                echo 'Tag is compliant with SemVar 2.0.0: $TAG_SEM_VER_COMPLIANT'
                echo 'Tag is Major release: $TAG_MAJOR_RELEASE'
                echo 'Tag is production: $TAG_PRODUCTION'
                echo 'Tag is staging: $TAG_STAGING'
                """
            }
        }
        stage('Build grafana-registry') {
            when {
                allOf {
                    // Triggered on every tag, that is considered for staging or production
                    expression{tag "*"}
                    expression{
                        TAG_STAGING == 'true' || TAG_PRODUCTION == 'true'
                    }
                }
             }
            steps {
                sh "cd CI-CD && ./make_docker.sh build grafana-registry"
            }
        }
        stage('Push grafana-registry to sodalite-private-registry') {
            // Push during staging and production
            when {
                allOf {
                    expression{tag "*"}
                    expression{
                        TAG_STAGING == 'true' || TAG_PRODUCTION == 'true'
                    }
                }
            }
            steps {
                withDockerRegistry(credentialsId: 'jenkins-sodalite.docker_token', url: '') {
                    sh  """#!/bin/bash
                        ./CI-CD/make_docker.sh push grafana-registry staging
                        """
                }
            }
        }
        stage('Push grafana-registry to DockerHub') {
            when {
                allOf {
                    // Triggered on every tag, that is considered for staging or production
                    expression{tag "*"}
                    expression{
                        TAG_PRODUCTION == 'true'
                    }
                }
             }
            steps {
                withDockerRegistry(credentialsId: 'jenkins-sodalite.docker_token', url: '') {
                    sh "./CI-CD/make_docker.sh push grafana-registry production"
                }
            }
        }
    }
}
