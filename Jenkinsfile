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

      stage('BOK Parallel Run'){
        parallel{
            stage("mu-deploy demo_recipes.yaml"){
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

            stage ("mu-deploy test_demo.yaml") {
              steps{
                  script{
                    try{
                        sh "python ${workspace}/test/exec_bok.py test_demo.yaml"
                      } catch {
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
      stage('inspec exec demo-test-profile'){
        parallel{
            stage("Run demo-test-profile"){
              steps {
                script{
                    sh "python ${workspace}/test/exec_inspec.py demo-test-profile demo_recipes.yaml"
                }
              }
            }

            stage ("inspec exec test-profile") {
              steps{
                  script{
                      sh "python /${workspace}/test/exec_inspec.py test test_demo.yaml"
                  }
              }
            }
        }
    }
  }
}

