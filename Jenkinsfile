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
      
      stage('Rubocop'){
        steps{
          script {
            sh "/usr/local/ruby-current/bin/rubocop ${workspace}/modules/"
          }
        }
      }

      stage('Foodcritic MU Cookbooks'){
        steps{
          script {
            sh "/usr/local/ruby-current/bin/foodcritic ${workspace}/cookbooks/*"
          }
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

//      stage('mu-deploy'){
//        parallel{
            stage("mu-deploy simple-server-rails"){
              steps {
                script{
                  try{
                      //sh "sleep 135"
                      sh "${workspace}/bin/mu-deploy -n ${workspace}/demo/simple-server-rails.yaml"
                    } catch (err) {
                      echo "ERROR: ${err}"
                      currentBuild.result = 'UNSTABLE'
                    }
                }
              }
            }

//            stage ("demo_recipes.yaml") {
//              steps{
//                  script{
//                    try{
//                        sh "python ${workspace}/test/exec_bok.py demo_recipes.yaml"
//                      } catch (err) {
//                        echo "ERROR: ${err}"
//                        currentBuild.result = 'UNSTABLE'
//                      }
                      
//                  }
//              }
//            }

//        }
//    }

// ****************************************************************
// ******************** Run ALL TESTS PARALLEL ********************
//      stage('Inspec Verify'){
//        parallel{
            stage("Inspec simple-server-rails-test"){
              steps {
                script{
                    try {
                      sh "python ${workspace}/test/exec_inspec.py simple-server-rails-test simple-server-rails.yaml"
                    } catch (err) {
                        echo "ERROR: ${err}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
              }
            }
            stage("Retry Failures")
            {
              steps {
                script {
                  try {
                    sh "python ${workspace}/test/exec_retry.py"
                  }
                  catch (err) {
                    echo "ERROR: ${err}"
                    currentBuild.result = 'UNSTABLE'
                  }
                }
              }
            }

//            stage ("demo-test-profile") {
//              steps{
//                  script{
//                    try{
//                      sh "python /${workspace}/test/exec_inspec.py demo-test-profile demo_recipes.yaml"
//                      } catch (err) {
//                        echo "ERROR: ${err}"
//                        currentBuild.result = 'UNSTABLE'
//                      }
//                  }
//              }
//            }
//        }
//    }
    stage('Mu-Cleanup'){
        steps {
          script {
            sh 'sudo python /opt/mu/lib/test/clean_up.py'
            sh 'sudo rm -rf /tmp/inspec_retries/*'
            sh 'sudo rm -f /tmp/*.yaml'
          }
        }
    }
  }
}

