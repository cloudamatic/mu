
peline {
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

// ***************************************************************
// ******************** Run ALL BOKS PARALLEL ********************

      stage('Clean Up & BOK Parallel Run'){
        parallel{

            stage('Initial Cleanup'){
                steps {
                    script {
                        sh 'sudo python /opt/mu/lib/test/clean_up.py'
                    }
                }
            }
            stage("Run demo recipes"){
              steps {
                script{
                    sh "sudo python /opt/mu/lib/test/exec_bok.py demo_recipes.yaml"
                }
              }
            }

            stage ('"Run test recipes') {
              steps{
                  script{
                      sh "sudo python /opt/mu/lib/test/exec_bok.py test_demo.yaml"
                  }
              }
            }
        }
    }

// ****************************************************************
// ******************** Run ALL TESTS PARALLEL ********************
      stage('BOK Parallel Inspec Tests'){
        parallel{
            stage("Run demo-test-profile"){
              steps {
                script{
                    sh "sudo python /opt/mu/lib/test/exec_inspec.py demo-test-profile demo_recipes.yaml"
                }
              }
            }

            stage ("Run simple-server-rails-test") {
              steps{
                  script{
                      sh "sudo python /opt/mu/lib/test/exec_inspec.py test test_demo.yaml"
                  }
              }
            }
        }
    }
  }
}

