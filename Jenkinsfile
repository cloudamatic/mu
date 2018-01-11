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
            stage("etco-autoscale-private.yaml"){
              steps {
                script{
                  try{
                      sh "sleep 135"
                      sh "${workspace}/bin/mu-deploy -n ${workspace}/demo/etco-autoscale-private.yaml -p s3_drive=etco-dev"
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

        }
    }

// ****************************************************************
// ******************** Run ALL TESTS PARALLEL ********************
      stage('Inspec Verify'){
        parallel{
            stage("etco-test"){
              steps {
                script{
                    try {
                      sh "python ${workspace}/test/exec_inspec.py etco-test-profile etco-autoscale-private.yaml"
                    } catch (err) {
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

