pipeline {
  agent any
  stages {
      stage ('git')
      {
        steps 
        {
          checkout([
            $class: 'GitSCM',
            branches: scm.branches,
            doGenerateSubmoduleConfigurations: false,
            extensions: scm.extensions + [[$class: 'SubmoduleOption', disableSubmodules: false, recursiveSubmodules: true, reference: '', trackingSubmodules: false]],
            submoduleCfg: [],
            userRemoteConfigs: scm.userRemoteConfigs])
        }
      }
      stage('Initial Cleanup'){
        steps {
          script {
            sh 'sudo python /opt/mu/lib/test/clean_up.py'
          }
        }
      }
// ***************************************************************
// ******************** Run ALL BOKS PARALLEL ********************

      stage('mu-deploy'){
        parallel{
            stage("demo_recipes.yaml"){
              steps {
                script{
                  try{
                      sh "python ${workspace}/test/exec_bok.py demo_recipes.yaml"
                    } catch (err) {
                      echo "ERROR: ${err}"
                      currentBuild.result = 'UNSTABLE'
                    }
                }
              }
            }

            stage ("test_demo.yaml") {
              steps{
                  script{
                    try{
                        sh "python ${workspace}/test/exec_bok.py test_demo.yaml"
                      } catch (err) {
                        echo "ERROR: ${err}"
                        currentBuild.result = 'UNSTABLE'
                      }
                      
                  }
              }
            }
        }
    }

// ****************************************************************
// ******************** Run ALL TESTS PARALLEL ********************
      stage('Inspec Verify'){
        parallel{
            stage("demo-test-profile"){
              steps {
                script{
                    try {
                      sh "python ${workspace}/test/exec_inspec.py demo-test-profile demo_recipes.yaml"
                    } catch (err) {
                        echo "ERROR: ${err}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
              }
            }

            stage ("test-profile") {
              steps{
                  script{
                    try{
                      sh "python /${workspace}/test/exec_inspec.py test test_demo.yaml"
                      } catch (err) {
                        echo "ERROR: ${err}"
                        currentBuild.result = 'UNSTABLE'
                      }
                  }
              }
            }
        }
    }
    stage('Mu-Cleanup'){
        steps {
          script {
            sh 'sudo python /opt/mu/lib/test/clean_up.py'
          }
        }
    }
  }
}

