node {
   stage('Git Clone') {
      git 'https://github.com/cloudamatic/mu.git'
  }
  stage('Clean up deployments'){
      sh "sudo python /opt/mu/lib/test/clean_up.py"
  }
  stage('Run Demo Recipes BOK'){
      sh "/opt/mu/bin/mu-deploy -n /opt/mu/lib/demo/demo_recipes.yaml"
  }
  stage('Verify with Inspec') {
      sh "sudo python /opt/mu/lib/test/demo_tests/exec_inspec.py"
  }
}
