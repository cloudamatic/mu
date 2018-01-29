# default['omnibus-gitlab']['gitlab_rb']['nginx']['redirect_http_to_https'] = true
# default['omnibus-gitlab']['gitlab_rb']['nginx']['ssl_certificate'] = '/etc/gitlab/ssl/git.femadata.com.crt'
# default['omnibus-gitlab']['gitlab_rb']['nginx']['ssl_certificate_key'] = '/etc/gitlab/ssl/femadata.key'
# default['omnibus-gitlab']['gitlab_rb']['nginx']['ssl_protocols'] = "TLSv1.2"


# SMTP Configuration   
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['smtp_enable'] = true
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['smtp_address'] = "ssmtp.gmail.com"
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['smtp_port'] = 456
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['smtp_domain'] = "gitlab.example.com"
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['smtp_authentication'] = "login"
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['smtp_enable_starttls_auto'] = true
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['gitlab_email_from'] = 'gitlab@femadata.com'


# Server Configuration
# node.default['omnibus-gitlab']['gitlab_rb']['git_data_dirs'] = ['/git/git-data']
default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['initial_root_password'] = "superman"
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['initial_shared_runners_registration_token'] = "superman"
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['gitlab_signup_enabled'] = false # THIS DOESNT WORK ANY MORE. :( I AM LEAVING IT HERE IN CASE THEY MAKE IT WORK AGAIN IN THE FUTURE.
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['gitlab_default_projects_features_issues'] = true
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['gitlab_default_projects_features_merge_requests'] = true
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['gitlab_default_projects_features_wiki'] = true
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['gitlab_default_projects_features_snippets'] = true
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['gitlab_default_projects_features_builds'] = true
# default['omnibus-gitlab']['gitlab_rb']['gitlab-rails']['gitlab_default_projects_features_container_registry'] = true


# I think this may have something to do with LDAP NEED TO FIX IT
# default['omnibus-gitlab']['gitlab_rb']['user']['group'] = 'herpderp'
# default['omnibus-gitlab']['gitlab_rb']['user']['gid'] = '1234'


# *****************GITLAB RUNNER***************


# RUNNER VERSION TO INSTALL
default['gitlab-ci-runner']['version'] = 'latest'

# AN ARRAY OF RUNNERS
default['gitlab-ci-runner']['runners'] = []

# THE SCRIPT URL = BASEURL + SCRIPTNAME
default['gitlab-ci-runner']['repository_base_url'] = 'https://packages.gitlab.com/install/repositories/runner/gitlab-runner/'
default['gitlab-ci-runner']['debScript'] = 'script.deb.sh'
default['gitlab-ci-runner']['rpmScript'] = 'script.rpm.sh'