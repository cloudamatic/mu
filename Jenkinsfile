node {
    
  def run_list = ['demo_recipes.yaml':'demo-test-profile', 'simple-server-rails.yaml':'simple-server-rails-test']
  
  stage('Git Clone') {
      git 'https://github.com/cloudamatic/mu.git'
  }
  
  stage('Initial Cleanup') {
      sh 'sudo python /opt/mu/lib/test/clean_up.py'
  }
 
  for (bok in run_list.keySet()) {
    def profile = "${run_list[bok]}"

   // ******************** Run BOK ********************
   try{   
      stage("Running BOK: ${bok}"){
        sh "sudo python /opt/mu/lib/test/exec_bok.py ${bok}"
      }
    }
    catch (err){
      echo "Caught: ${err}"
      currentBuild.result = 'UNSTABLE'
    }

    // ****************** Run Inspec *****************
    try{
      stage("Inspec Test: ${profile}"){
        sh "sudo python /opt/mu/lib/test/exec_inspec.py ${profile}"
      }
    }
    catch(err){
      echo "Caught: ${err}"
      currentBuild.result = 'UNSTABLE'
    }
    
    // ****************** Clean Up *******************
    stage("Clean up: ${bok}") {
      sh 'sudo python /opt/mu/lib/test/clean_up.py'
    }
  }
}
