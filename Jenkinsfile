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
            sh 'sudo rm  -rf /tmp/inspec_retries/*'
            sh 'sudo rm -f /tmp/*.yaml'
          }
        }
      }

//-----------------------------------------------------------------------------------------


      stage('Lint && mu-deploy'){
        parallel{
            
          stage('Rubocop'){
            steps{
              script {
                try {
                  sh "/usr/local/ruby-current/bin/rubocop ${workspace}/modules/"
                } catch(err) {
                    echo "ERROR: ${err}"
                    currentBuild.result = 'SUCCESS'
                }
              }
            }
          }  

          stage('Foodcritic MU Cookbooks'){
            steps{
              script {
                try {
                  sh "/usr/local/ruby-current/bin/foodcritic ${workspace}/cookbooks/*"
                } catch (err) {
                    echo "ERROR: ${err}"
                    currentBuild.result = 'SUCCESS'
                }
              }
            }
          }    


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
            
            stage("mu-master-install"){
              steps{
                script {
                  try{
                    sh "${workspace}/test/exec_mu_install.py"
                  } catch (err) {
                      echo "ERROR: ${err}"
                      currentBuild.result = 'UNSTABLE'
                  }
                }
              }
            }

//            stage ("wordpress.yaml") {
//              steps{
//                  script{
//                    try{
//                        sh "sleep 145"
//                        sh "${workspace}/bin/mu-deploy -n ${workspace}/demo/demo_recipes.yaml"
//                      } catch (err) {
//                        echo "ERROR: ${err}"
//                        currentBuild.result = 'UNSTABLE'
//                      }
//                 }
//              }
//            }
        }
    }


//-----------------------------------------------------------------------------------------


//      stage('Inspec Verify'){
//        parallel{
            stage("Inspec simple-server-rails"){
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
