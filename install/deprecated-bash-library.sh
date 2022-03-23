#!/bin/sh
#
# This script installs and configures (or reconfigures) an Mu Master,
# setting up the Mu tools, Chef, and assorted support libraries and utilities.
#

# clean containing environment of nonsense
unset GEM_HOME
unset GEM_PATH

DIST_VERSION=`rpm -qa \*-release\* | grep -Ei "redhat|centos" | cut -d"-" -f3`
IS_AMAZON=0
if [ "$DIST_VERSION" == "" ];then # funny package name in Amazon Linux
#  DIST_VERSION=`rpm -qa \*-release\* | cut -d"-" -f3` # XXX always 6 for now
  DIST_VERSION=6
  IS_AMAZON=1
elif [ "$DIST_VERSION" == "server" ];then # funny package name in RHEL6
  DIST_VERSION="6"
fi
EPEL_RPM="http://mirror.metrocast.net/fedora/epel/epel-release-latest-$DIST_VERSION.noarch.rpm"

CHEF_CLIENT_VERSION="12.17.44-1"
CHEF_SERVER_VERSION="12.11.1-1"

if [ "$DIST_VERSION" == "7" ];then
  # mariadb replaces mysql, qt and qt-x11 are required by gecode which is required by the dep_selector gem. 
  PACKAGES="git curl vim-enhanced zip unzip java-1.8.0-openjdk gcc gcc-c++ make libxml2-devel libxslt-devel cryptsetup-luks python-pip lsof mlocate strace nmap openssl-devel readline-devel python-devel ImageMagick-devel diffutils patch bind-utils httpd-tools gecode-devel mailx postgresql-devel openssl libyaml graphviz graphviz-devel mariadb mariadb-devel qt qt-x11 iptables-services jq"
  DEL_PACKAGES="nagios firewalld"
  OPSCODE_CHEF_PKG="chef-server-core-$CHEF_SERVER_VERSION.el7.x86_64"
  OPSCODE_CHEF_DL="https://packages.chef.io/stable/el/7/${OPSCODE_CHEF_PKG}.rpm"
  CHEF_CLIENT_PKG="chef-$CHEF_CLIENT_VERSION.el7.x86_64"
  RUBY_RPM="https://s3.amazonaws.com/cloudamatic/ruby23-2.3.1-1.el7.centos.x86_64.rpm"
  RUBY_INSTALL_DIR="/opt/rubies/ruby-2.3.1"
  RUBY_VERSION="ruby23-2.3.1"
  GECODE_RPMS="https://s3.amazonaws.com/cap-public/gecode-3.7.3-2.el7.centos.x86_64.rpm https://s3.amazonaws.com/cap-public/gecode-devel-3.7.3-2.el7.centos.x86_64.rpm"
else
  PACKAGES="git curl vim-enhanced zip unzip java-1.5.0-gcj java-1.8.0-openjdk mysql-server gcc gcc-c++ make libxml2-devel libxslt-devel cryptsetup-luks python-pip lsof mlocate strace nmap openssl-devel readline-devel python-devel diffutils patch bind-utils httpd-tools mailx mysql-devel postgresql-devel openssl libyaml graphviz autoconf ImageMagick-devel graphviz-devel jq"
  if [ "$IS_AMAZON" != "1" ];then
    PACKAGES="${PACKAGES} gecode-devel"
#  else
#    PACKAGES="${PACKAGES} "
  fi
  OPSCODE_CHEF_PKG="chef-server-core-$CHEF_SERVER_VERSION.el6.x86_64"
  OPSCODE_CHEF_DL="https://packages.chef.io/stable/el/6/${OPSCODE_CHEF_PKG}.rpm"
  CHEF_CLIENT_PKG="chef-$CHEF_CLIENT_VERSION.el6.x86_64"
  RUBY_RPM="https://s3.amazonaws.com/cloudamatic/ruby23-2.3.1-1.el6.x86_64.rpm"
  RUBY_INSTALL_DIR="/opt/rubies/ruby-2.3.1"
  RUBY_VERSION="ruby23-2.3.1"
  DEL_PACKAGES="nagios"
fi

if ! curl --fail http://169.254.169.254/latest/meta-data/instance-id > /dev/null 2>&1;then
  IN_AWS=0
else
  GET_METADATA="curl --fail -s -S http://169.254.169.254/latest"
  IN_AWS=1
fi
if ! curl --fail http://metadata.google.internal/computeMetadata/v1/instance/name -H "Metadata-Flavor: Google" > /dev/null 2>&1;then
  IN_GOOGLE=0
else
  GET_METADATA="curl --fail -s -S http://metadata.google.internal/computeMetadata/v1"
  IN_GOOGLE=1
fi

RCFILE=".murc"

#tput will cause a noninteractive session to silently fail, else color things
if [ -t 0 ]; then
  BOLD=`tput bold`
  NORM=`tput sgr0`
  BLACK=`tput setaf 0`
  RED=`tput setaf 1`
  GREEN=`tput setaf 2`
  YELLOW=`tput setaf 3`
  BLUE=`tput setaf 4`
  PINK=`tput setaf 5`
  CYAN=`tput setaf 6`
  WHITE=`tput setaf 7`
fi

export PATH="/bin:/usr/bin:/sbin:/usr/sbin"

# Non-root users can only customize certain configuration parameters
if [ "root" == "`whoami`" ];then
  CONFIG_VARS="AWS_ACCESS AWS_SECRET MU_ADMIN_EMAIL MU_ADMIN_PW JENKINS_ADMIN_PW MU_INSTALLDIR MU_DATADIR ADDTL_CHEF_REPOS MU_REPO CHEF_PUBLIC_IP HOST_NAME EC2SECGROUP LOG_BUCKET_NAME ALLOW_INVADE_FOREIGN_VPCS MU_SSL_CERT MU_SSL_KEY MU_SSL_CHAIN"
  RO_CONFIG_VARS="AWS_ACCOUNT_NUMBER EC2_REGION"
else
  CONFIG_VARS="AWS_ACCESS AWS_SECRET MU_DATADIR ADDTL_CHEF_REPOS MU_REPO LOG_BUCKET_NAME"
  RO_CONFIG_VARS="AWS_ACCOUNT_NUMBER EC2_REGION CHEF_PUBLIC_IP HOST_NAME EC2SECGROUP MU_INSTALLDIR"
fi

usage()
{
  echo "Create or reconfigure your Chef master."
  echo "Usage: $0 [-d] [-c /path/to/murc] [-b branch]"
  echo "    -d: Use default values and run non-interactively."
  echo "    -b: Choose a branch (default: master)."
  echo "    -c: Use an alternate .murc file."
  echo "    -k: Run curl with -k to skip SSL certificate checks."
  exit 1
}

_me="`basename $0`"
#if  [ "$_me" == "mu-configure" ];then
#  chef_artifacts_uploaded=1
#  if [ -d "$MU_LIBDIR/.git" ]; then
#    cd $MU_LIBDIR
#    MUBRANCH="`git branch 2>/dev/null | egrep '^\*' |cut -d' ' -f2`"
#  fi
#fi

if [ "$_me" == "mu-self-update" ];then
  library=1
fi
if [ "$_me" == "mu-upload-chef-artifacts" ];then
  library=1
fi
if [ "$_me" == "mu-user-manage" ];then
  library=1
fi
curl_dash_k=1
chef_self_test=0
if [ "$library" != "1" ];then
  while getopts "c:tdhkb:" opt; do
    case $opt in
      c)
        MURC=$OPTARG
        ;;
      d)
        use_defaults=1
        ;;
      b)
        MUBRANCH=$OPTARG
        ;;
      k)
        curl_dash_k=1
        ;;
      h)
        usage
        ;;
      \?)
        usage
        ;;
    esac
  done
else
  set +e
  set +x
fi

umask 0077

# Populate key environment variables. Default them to whatever's set in the
# environment we've inherited, and failing that, see if we can extract some of
# them from this instance's EC2 metadata.
USER=`whoami`
if [ "$MU_INSTALLDIR" == "" ];then
  MU_INSTALLDIR="/opt/mu"
fi
if [ "$MU_SSL_CERT" == "" ];then
  MU_SSL_CERT="/opt/mu/var/ssl/mommacat.crt"
fi
if [ "$MU_SSL_KEY" == "" ];then
  MU_SSL_KEY="/opt/mu/var/ssl/mommacat.key"
fi
if [ "$MU_SSL_CHAIN" == "" ];then
  MU_SSL_CHAIN="/opt/mu/var/ssl/Mu_CA.pem"
fi
HOMEDIR="`getent passwd \"$USER\" |cut -d: -f6`"
MU_CHEF_CACHE="$HOMEDIR/.chef"
if [ -z $MU_DATADIR ];then
  if [ "$USER" != "root" ];then
    MU_DATADIR="$HOMEDIR/.mu"
  else
    MU_DATADIR="$MU_INSTALLDIR/var"
  fi
fi
if [ "$MU_LIBDIR" == "" ];then
  MU_LIBDIR="$MU_INSTALLDIR/lib"
fi
if [ "$MURC" == "" ];then
  if [ "$USER" != "root" ];then
    MURC="$HOMEDIR/$RCFILE"
  else
    MURC="$MU_INSTALLDIR/etc/mu.rc"
    test -f "$MU_INSTALLDIR/etc/mu.rc" || ( mkdir -p $MU_INSTALLDIR/etc && touch "$MU_INSTALLDIR/etc/mu.rc" )
    chmod 755 $MU_INSTALLDIR/etc
  fi
fi

# Source the global .murc file, then overlay the local one if it exists
test -f "$MU_INSTALLDIR/etc/mu.rc" && source "$MU_INSTALLDIR/etc/mu.rc"
if [ -f "$MURC" -a "$MURC" != "$MU_INSTALLDIR/etc/mu.rc" ] ;then
  source $MURC
fi

MU_REPO='cloudamatic/mu.git'
if [ "$MUBRANCH" == "" ];then
  if [ -d "$MU_LIBDIR/.git" ]; then
    cd $MU_LIBDIR
    MUBRANCH="`git branch 2>/dev/null | grep '^\*' | awk '{print $2}'`"
  fi
  if [ "$MUBRANCH" == "" ];then
    MUBRANCH="master"
  fi
fi
MU_REPO_NAME="`echo $MU_REPO | cut -d/ -f2 | sed -e 's/\.git$//'`"
MY_PRIVATE_IP=""
if [ "$IN_AWS" == "1" ];then
  if [ "$EC2_AVAILABILITY_ZONE" == "" ];then
    EC2_AVAILABILITY_ZONE=`$GET_METADATA/meta-data/placement/availability-zone`
  fi
  if [ "$EC2_REGION" == "" ];then
    EC2_REGION=`$GET_METADATA/dynamic/instance-identity/document|grep region|awk -F\" '{print $4}'`
  fi
  if [ "$AWS_ACCOUNT_NUMBER" == "" ];then
    AWS_ACCOUNT_NUMBER=`$GET_METADATA/dynamic/instance-identity/document|grep accountId|awk -F\" '{print $4}'`
  fi
  ip_pattern='^[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+$'
  MY_INSTANCE_ID="`$GET_METADATA/meta-data/instance-id`"
  MY_PRIVATE_IP="`$GET_METADATA/meta-data/local-ipv4 | egrep \"$ip_pattern\"`"
  MY_PUBLIC_IP="`$GET_METADATA/meta-data/public-ipv4 2>&1 | egrep \"$ip_pattern\"`"
  if [ "$MY_PRIVATE_IP" == "" ];then
    echo "Couldn't determine my private IP with '$GET_METADATA/meta-data/local-ipv4'"
    exit 1
  fi
elif [ "$IN_GOOGLE" == "1" ];then
  MY_INSTANCE_ID="`$GET_METADATA/instance/name -H 'Metadata-Flavor: Google'`"
  MY_PRIVATE_IP="`$GET_METADATA/instance/network-interfaces/0/ip -H 'Metadata-Flavor: Google'`"
  if [ "$MY_PRIVATE_IP" == "" ];then
    echo "Couldn't determine my private IP with '$GET_METADATA/instance/network-interfaces/0/ip'"
    exit 1
  fi
#  MY_PUBLIC_IP="`$GET_METADATA/meta-data/public-ipv4 | egrep \"$ip_pattern\"`"
fi
if [ "$CHEF_PUBLIC_IP" == "" -a "$MY_PUBLIC_IP" != "" ];then
  CHEF_PUBLIC_IP=$MY_PUBLIC_IP
fi
if [ "$MY_PUBLIC_IP" == "" ];then
  MY_PUBLIC_IP=$MY_PRIVATE_IP
fi
if [ "$HOST_NAME" == "" ];then
  HOST_NAME="`hostname -s`"
fi
MY_VPC_ID=""
# Figure out if we have at least one interface in a VPC
if [ "$IN_AWS" == "1" ];then
  if [ "$LOG_BUCKET_NAME" == "" ];then
    LOG_BUCKET_NAME="mu-logs-${HOST_NAME}-${MY_INSTANCE_ID}"
  fi
  for mac in `$GET_METADATA/meta-data/network/interfaces/macs/`;do
    vpc_id="`$GET_METADATA/meta-data/network/interfaces/macs/$mac/vpc-id | egrep '^vpc\-'`"
    if [ "$vpc_id" != "" ];then
      MY_VPC_ID=$vpc_id
      break
    fi
  done
  IAM_ROLE="`$GET_METADATA/meta-data/iam/security-credentials/ 2> /dev/null`"
fi

###############################################################################
fail_with_message()
{
  if [ "$1" != "" ];then
    echo ""
    echo "${RED}*******************************************************************************${NORM}"
    echo "${RED}*******************************************************************************${NORM}"
    echo $1
    test "$2" != "" && echo $2
    echo "${RED}*******************************************************************************${NORM}"
    echo "${RED}*******************************************************************************${NORM}"
    echo ""
  fi
  exit 1
}

###############################################################################
warning_message()
{
  if [ "$1" != "" ];then
    echo ""
    echo "${YELLOW}*******************************************************************************${NORM}"
    echo $1
    test "$2" != "" && echo $2
    echo "${YELLOW}*******************************************************************************${NORM}"
    echo ""
  fi
}

###############################################################################
status_message()
{
  if [ "$1" != "" ];then
    echo ""
    echo "${GREEN}*******************************************************************************${NORM}"
    echo $1
    test "$2" != "" && echo $2
    echo "${GREEN}*******************************************************************************${NORM}"
    echo ""
  fi
}

###############################################################################
# Useful for accessing our parallel key/value structure.  
# Accepts named key as argument
# Returns value of target env variable from array structures
# Uses stdout so do **not** echo or printf in this function
###############################################################################

return_targetvar_value()

{
    for i in "${!var_name[@]}"; do

      if [ ${var_name[$i]}  = "$1" ]; then
         printf '%s' ${var_val[$i]}
        break
      fi
    done
}



###############################################################################
update_murc()
{
  name="$1"
  value="$2"
  murc_path="$3"
  if [ "$murc_path" == "" ];then
    murc_path="$MURC"
  fi
  if [ "$name" == "" ];then
    fail_with_message "update_murc called with missing variable name"
  fi
  test -f $murc_path && sed -i "/^export $name=.*/d" $murc_path
  echo "export $name=\"$value\"" >> $murc_path
  chmod 644 $murc_path
}

###############################################################################
set_path_env_vars()
{
  MU_REPO_NAME="`echo $MU_REPO | cut -d/ -f2 | sed -e 's/\.git$//'`"
  HOMEDIR="`getent passwd \"$USER\" |cut -d: -f6`"
  MU_CHEF_CACHE="$HOMEDIR/.chef"
  SSHDIR="$HOMEDIR/.ssh"
  ENVFILE="$HOMEDIR/.bash_profile"
  mkdir -p $MU_INSTALLDIR/etc $MU_INSTALLDIR/bin $MU_DATADIR/deployments
  chmod 755 $MU_INSTALLDIR $MU_DATADIR
  DEVOPS_TMP_DIR='/tmp/.mu.$$'
  update_murc MU_INSTALLDIR $MU_INSTALLDIR
  update_murc MU_DATADIR $MU_DATADIR
  AWS_ACCESS_KEY_ID=$AWS_ACCESS
  AWS_SECRET_ACCESS_KEY=$AWS_SECRET
}

pivotal_cfg_setup(){
  port=$2
  if [ "$port" == "" ];then
    port=7443
  fi
  cat >> /etc/opscode/pivotal.rb.tmp.$$ << EOF
node_name "pivotal"
chef_server_url "https://${CHEF_PUBLIC_IP}:$port"
chef_server_root "https://${CHEF_PUBLIC_IP}:$port"
client_key "/etc/opscode/pivotal.pem"
ssl_verify_mode :verify_none
EOF
  if [ ! -f /etc/opscode/pivotal.rb -o "`diff /etc/opscode/pivotal.rb /etc/opscode/pivotal.rb.tmp.$$`" != "" ];then
    /bin/mv -f /etc/opscode/pivotal.rb.tmp.$$ /etc/opscode/pivotal.rb
  fi
  pivotal_pem="/opt/opscode/embedded/service/omnibus-ctl/spec/fixtures/pivotal.pem"
  if [ -f /etc/opscode/pivotal.pem ];then
    pivotal_pem="/etc/opscode/pivotal.pem"
  fi
  pivotal_cfg="-u pivotal -k $pivotal_pem"
  knife ssl fetch $pivotal_cfg > /dev/null 2>&1
  eval "$1=\"$pivotal_cfg\""
}

remove_chef_org()
{
  org="$1"

  pivotal_cfg_setup pivotal_cfg
  # chef-server-ctl generates a spectcular amount of stupid noise
  filter="(ffi-yajl|falling back to ffi)"

  if ! /opt/opscode/bin/chef-server-ctl org-list $pivotal_cfg 2>&1 | egrep -v "$filter" | grep "^$org$" >/dev/null;then
    warning_message "Chef org ${BOLD}$org${NORM} already removed"
  else
    status_message "Deleting Chef org ${BOLD}$org${NORM}"
    /opt/opscode/bin/chef-server-ctl org-delete -y "$org" $pivotal_cfg 2>&1 | egrep -v "$filter"
  fi
}

manage_chef_org()
{
  org=$1
  orgname=$2
  add_user=$3
  association_user=$4

  if curl -k -so /dev/null https://${CHEF_PUBLIC_IP}:7443;then 
    pivotal_cfg_setup pivotal_cfg
  else
    pivotal_cfg_setup pivotal_cfg 443
  fi

  # chef-server-ctl generates a spectcular amount of stupid noise
  filter="(ffi-yajl|falling back to ffi)"

  if [ "$orgname" == "" ];then
    orgname="$org"
  fi

  mkdir -p $MU_DATADIR/orgs/$org

  assoc=""
  if [ "$association_user" != "" ];then
    assoc="-a $association_user"
  fi
  keypath="$MU_DATADIR/orgs/$org/$org.org.key"
  if ! /opt/opscode/bin/chef-server-ctl org-list $pivotal_cfg 2>&1 | egrep -v "$filter" | grep "^$org$" >/dev/null;then
    if [ "$association_user" != "" ];then
      status_message "Creating Chef organization ${BOLD}$org${NORM} with admin user ${BOLD}$association_user${NORM}"
    else
      status_message "Creating Chef organization ${BOLD}$org${NORM}"
    fi
    attempts=0

    while : ;do
      /bin/rm -f $keypath
      cmd="/opt/opscode/bin/chef-server-ctl org-create $org $orgname $assoc -f $keypath $pivotal_cfg"
      $cmd 2>&1 | egrep -v "$filter"
      test -f $keypath && grep 'BEGIN RSA PRIVATE KEY' $keypath > /dev/null && break
      attempts=`expr $attempts + 1`
      if [ $attempts -gt 5 ];then
        output="`$cmd 2>&1 | egrep -v \"$filter\"`"
        warning_message "Unable to set up Chef org ${BOLD}$org${NORM}" "$cmd: $output"  
        break
      fi
    done
    if [ "$association_user" != "" ];then
      if [ "$association_user" != "mu" ];then
        user_home="`getent passwd \"$association_user\" |cut -d: -f6`"
      else
        user_home="`getent passwd \"root\" |cut -d: -f6`"
      fi
      mkdir -p "$user_home/.chef"
      /bin/cp -f "$keypath" "$user_home/.chef/"
    fi
  fi

  if [ "$add_user" != "" -a "$add_user" != "$association_user" ];then
    status_message "Adding ${BOLD}$add_user${NORM} to Chef organization ${BOLD}$org${NORM}"
    cmd="/opt/opscode/bin/chef-server-ctl org-user-add $org $add_user $pivotal_cfg"
    $cmd 2>&1 | egrep -v "$filter"
    if [ "$org" != "mu" ];then
      if [ "$add_user" != "mu" ];then
        user_home="`getent passwd \"$add_user\" |cut -d: -f6`"
      else
        user_home="`getent passwd \"root\" |cut -d: -f6`"
      fi
      mkdir -p "$user_home/.chef"
      /bin/cp -f "$keypath" "$user_home/.chef/"
    fi
  fi
#   warning_message "Failed to add ${BOLD}$user${NORM} to Chef org ${BOLD}$org${NORM}" "$cmd"
}

remove_chef_user_from_org()
{
  user="$1"
  org="$2"

  pivotal_cfg_setup pivotal_cfg
  # chef-server-ctl generates a spectcular amount of stupid noise
  filter="(ffi-yajl|falling back to ffi)"

  status_message "Removing ${BOLD}$user${NORM} from Chef org ${BOLD}$org${NORM}"

  /opt/opscode/bin/chef-server-ctl org-user-remove "$org" "$user" -y $pivotal_cfg 2>&1 | egrep -v "$filter"
}

remove_chef_user()
{
  user="$1"

  pivotal_cfg_setup pivotal_cfg
  # chef-server-ctl generates a spectcular amount of stupid noise
  filter="(ffi-yajl|falling back to ffi)"

  if ! /opt/opscode/bin/chef-server-ctl user-list $pivotal_cfg 2>&1 | egrep -v "$filter" | grep "^$user$" >/dev/null;then
    warning_message "Chef user ${BOLD}$user${NORM} already removed"
  else
    remove_chef_org "$user"
    for org in `/opt/opscode/bin/chef-server-ctl user-show $user --with-orgs $pivotal_cfg 2>&1 | egrep -v "$filter" | grep ^organizations: |cut -d: -f2`;do
      remove_chef_user_from_org "$user" "$org"
    done
    status_message "Deleting Chef user ${BOLD}$user${NORM}"
    /opt/opscode/bin/chef-server-ctl user-delete "$user" -y $pivotal_cfg 2>&1 | egrep -v "$filter"
  fi
}

list_chef_users(){
  # chef-server-ctl generates a spectcular amount of stupid noise
  filter="(ffi-yajl|falling back to ffi)"
  list="`/opt/opscode/bin/chef-server-ctl user-list 2>&1 | egrep -v \"$filter\" | egrep -v '^(pivotal)$' | tr -s '\n' ' '`"
  eval "$1=\"$list\""
}


manage_chef_user()
{
  user="$1"
  pass="$2"
  name="$3"
  email="$4"
  org="$5"
  is_admin="$6"
  is_normal="$7"
  replace="$8"

  if [ "$is_admin" == "1" -a "$is_normal" == "1" ];then
    fail_with_message "Can't force-set a Chef user to both administrator and regular user"
  fi

  mkdir -p "$MU_DATADIR/users/$user"
  /bin/chmod g+rsx "$MU_DATADIR/users"
  /bin/chgrp mu-users "$MU_DATADIR/users"

  if curl -k -so /dev/null https://${CHEF_PUBLIC_IP}:7443;then 
    pivotal_cfg_setup pivotal_cfg
  else
    pivotal_cfg_setup pivotal_cfg 443
  fi

  # chef-server-ctl generates a spectcular amount of stupid noise
  filter="(ffi-yajl|falling back to ffi)"

  if ! ( [ -f "$MU_DATADIR/users/$user/$user.user.key" ] && /opt/opscode/bin/chef-server-ctl user-list 2>&1 | egrep -v "$filter" | grep "^$user$" >/dev/null );then
    ok=1
    if [ "$name" == "" ];then
      warning_message "Must supply a real name to create new Chef user ${BOLD}$user${NORM}"
      ok=0
    fi
    if [ "$email" == "" ];then
      warning_message "Must supply an email address to create new Chef user ${BOLD}$user${NORM}"
      ok=0
    fi
    if [ "$pass" == "" ];then
      warning_message "Must supply a password to create new Chef user ${BOLD}$user${NORM}"
      ok=0
    fi
    if [ "$ok" != "1" ];then
      return
    fi
    status_message "Creating Chef user ${BOLD}$user${NORM} - $name ($email)"
    attempts=0
    keypath="$MU_DATADIR/users/$user/$user.user.key"
    if [ ! -f "$MU_DATADIR/users/$user/$user.user.key" -a "$replace" != "" ];then
      /opt/opscode/bin/chef-server-ctl user-delete "$user" -y $pivotal_cfg 2>&1 | egrep -v "$filter"
    fi
    create_cmd="/opt/opscode/bin/chef-server-ctl user-create $user $name $email $pass $pivotal_cfg -f $keypath"
    while : ;do
      /bin/rm -f "$keypath"
      # XXX Flinging passwords around CLI calls is terrible, need a better way
      # to do this. Maybe we need local-brew directory services.
      $create_cmd 2>&1 | egrep -v "$filter"
      test -f "$keypath" && grep 'BEGIN RSA PRIVATE KEY' "$keypath" > /dev/null && break
      attempts=`expr $attempts + 1`
      if [ $attempts -gt 5 ];then
        output="`$create_cmd 2>&1 | egrep -v \"$filter\"`"
        warning_message "Unable to set up Chef ${BOLD}$user${NORM} user" "$create_cmd: $output" 
        break
      fi
    done
    if [ "$user" != "mu" ];then
      user_home="`getent passwd \"$user\" |cut -d: -f6`"
    else
      user_home="`getent passwd \"root\" |cut -d: -f6`"
    fi
    mkdir -p "$user_home/.chef"
    /bin/cp -f "$keypath" "$user_home/.chef/"

    manage_chef_org "$user" "$user" "" "$user"
    set_knife_rb "organizations/$user" "$user" "https://${CHEF_PUBLIC_IP}:7443"

    status_message "Configuring ${BOLD}$user_home/.chef/client.rb${NORM}"
    cat /dev/null > "$user_home/.chef/client.rb"
    cat >> "$user_home/.chef/client.rb" << EOF
#
# Client settings
#
log_level        :info
log_location     STDOUT
chef_server_url  "https://${CHEF_PUBLIC_IP}:7443/organizations/$user"
validation_client_name '$user-validator'
EOF
    if [ "$user" != "mu" ];then
      chown -R "$user" "$user_home/.chef/"
      runuser -l "$user" -c "cd $user_home && /opt/chef/bin/knife ssl fetch" > /root/knifesslfetch.out 2>&1
    else
      /opt/chef/bin/knife ssl fetch > /dev/null 2>&1
    fi


    if [ "$add_org" != "" ];then
      manage_chef_org "$add_org" "$add_org" "$user" "mu"
    fi
    if [ "$is_admin" == "1" ];then
      manage_chef_org "mu" "" "$user"
    elif [ "$is_normal" == "1" ];then
      remove_chef_user_from_org "$user" "mu"
    fi
  else
    status_message "Updating Chef user ${BOLD}$user${NORM}"
    if [ "$add_org" != "" ];then
      manage_chef_org "$add_org" "$add_org" "$user" "mu"
    fi
    if [ "$is_admin" == "1" ];then
      manage_chef_org "mu" "" "$user"
    elif [ "$is_normal" == "1" ];then
      remove_chef_user_from_org "$user" "mu"
    fi
    if [ "$password" != "" ];then
      warning_message "You'll have to enter the new password again for Chef" "Also it will display it back to you in plain text. Yeah."
      /opt/opscode/bin/chef-server-ctl password $user
    fi
  fi
}


###############################################################################
validate_setup_env_vars(){
  n=1
  validate_errs=0
  while [ "${var_name[$n]}" != "" ];do
    if [ "${var_name[$n]}" == "AWS_ACCESS" -o "${var_name[$n]}" == "AWS_SECRET" ]; then
      if [ "$IAM_ROLE" == "" -a "${var_val[$n]}" == "" ];then
        warning_message "No IAM instance profile assigned to this server. You must specify AWS credentials."
        validate_errs=1
      fi
    elif [ "${var_name[$n]}" == "CHEF_PUBLIC_IP" ]; then
      if [ "${var_val[$n]}" == "" ];then
        warning_message "An IP accessible to client nodes must be specified"
        validate_errs=1
      fi  
    elif [ "${var_name[$n]}" == "MU_ADMIN_EMAIL" ]; then
      if [ "${var_val[$n]}" == "" ];then
        warning_message "You must specify an email contact for the 'mu' admin user."
        validate_errs=1
      elif ! ( echo ${var_val[$n]} | egrep -q '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$' ) ; then
        warning_message "The 'mu' admin user email contact is badly formed!"
        validate_errs=1
      fi  

    elif [ "${var_name[$n]}" == "MU_ADMIN_PW" -a ! -f "$MU_CHEF_CACHE/mu.user.key" ]; then
      if [ "${var_val[$n]}" == "" ];then
        warning_message "You must specify a password for the 'mu' admin user."
        validate_errs=1
      fi  

    elif [ "${var_name[$n]}" == "LOG_BUCKET_NAME" ]; then
      if [ "${var_val[$n]}" == "" ];then
        warning_message "You must specify a dns-legal log bucket name ."
        validate_errs=1
      elif ! ( echo ${var_val[$n]} | egrep -q '^[a-z0-9.-]*$' ) ; then
        warning_message "The log bucket name is badly formed!"
        validate_errs=1
      fi  

    elif [ "${var_name[$n]}" == "JENKINS_ADMIN_PW" ]; then
      if [ "${var_val[$n]}" == "" ];then
        warning_message "You must specify a password for the 'jenkins' admin user to enable the Jenkins front-end. Jenkins will not be enabled at this time. Rerun mu-configure and supply a password if you wish to enable it."
        sleep 5
      fi  
    fi
    n=$[$n +1]
  done

  MU_ADMIN_EMAIL_VAL=$(return_targetvar_value "MU_ADMIN_EMAIL")
  JENKINS_ADMIN_EMAIL_VAL=$(return_targetvar_value "MU_ADMIN_EMAIL")

}

###############################################################################
print_setup_env_vars(){
  echo "${CYAN}System-wide settings${NORM}:"
  for ro in $RO_CONFIG_VARS;do
      echo "  ${BOLD}$ro${NORM}: ${CYAN}${!ro}${NORM}"
  done
  echo "${GREEN}Configurable settings to write to ${BOLD}$MURC${NORM}:"
  n=1
  while [ "${var_name[$n]}" != "" ];do
    if [ "${var_name[$n]}" == "CHEF_PUBLIC_IP" ]; then
      if [ "$MY_VPC_ID" != "" ];then
        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (if in private subnet, set to bastion public IP): ${GREEN}${var_val[$n]}${NORM}"
      else
        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (OPTIONAL; will try to guess): ${GREEN}${var_val[$n]}${NORM}"
      fi 
    elif [ "${var_name[$n]}" == "AWS_ACCESS" -o "${var_name[$n]}" == "AWS_SECRET" ]; then
      if [ "$IAM_ROLE" != "" ];then

        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (N/A if IAM role ${BOLD}$IAM_ROLE${NORM} has admin privs): ${GREEN}${var_val[$n]}${NORM}"
      else
        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (required): ${GREEN}${var_val[$n]}${NORM}"
      fi
    elif [ "${var_name[$n]}" == "MU_ADMIN_EMAIL" ]; then
      echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (required): ${GREEN}${var_val[$n]}${NORM}"
    elif [ "${var_name[$n]}" == "MU_ADMIN_PW" ]; then
      if [ "${var_val[$n]}" != "" -o -f "$MU_CHEF_CACHE/mu.user.key" ];then
        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (required): ********"
      else
        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (required):"
      fi
    elif [ "${var_name[$n]}" == "JENKINS_ADMIN_PW" ]; then
      if [ "${var_val[$n]}" != "" ];then
        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (OPTIONAL): ********"
      else
        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (OPTIONAL):"
      fi
    elif [ "${var_name[$n]}" == "EC2SECGROUP" ]; then
      if [ "$MY_VPC_ID" == "" ];then
        echo "  ${BOLD}$n${NORM}) ${var_name[$n]} (OPTIONAL; will try to guess): ${GREEN}${var_val[$n]}${NORM}"
      fi 
    else
      echo "  ${BOLD}$n${NORM}) ${var_name[$n]}: ${GREEN}${var_val[$n]}${NORM}"
    fi
    n=$[$n +1]
  done
}

chef_client()
{
  punch_tcp_hole 7443 # sometimes this isn't ready
  upload_chef_artifacts -n -r $MU_REPO_NAME
  status_message "chef-client $@"

  chef_cert_name="`echo $CHEF_PUBLIC_IP | sed 's/\./_/g'`"

  /bin/cp -f /opt/mu/var/ssl/Mu_CA.pem /etc/chef/trusted_certs/
  if (knife ssl check -c /etc/chef/client.rb | egrep "^ERROR.*certificate");then
    /bin/rm -f /etc/chef/trusted_certs/${chef_cert_name}.crt
    /bin/rm -f /etc/chef/trusted_certs/${HOST_NAME}_platform-mu.crt
    /opt/chef/bin/knife ssl fetch -c /etc/chef/client.rb
  fi
  # Same, but for /root/.chef/trusted_certs
  /bin/cp -f /opt/mu/var/ssl/Mu_CA.pem /root/.chef/trusted_certs/
  if (knife ssl check | egrep "^ERROR.*certificate");then
    /bin/rm -f /root/.chef/trusted_certs/${chef_cert_name}.crt
    /bin/rm -f /root/.chef/trusted_certs/${HOST_NAME}_platform-mu.crt
    /opt/chef/bin/knife ssl fetch
  fi
  chef-client $@

}

###############################################################################
chef_server_ctl()
{
  cmd=$1
  pivotal_cfg_setup pivotal_cfg
  status_message "/opt/opscode/bin/chef-server-ctl $cmd"
  if ! /opt/opscode/bin/chef-server-ctl $cmd > /dev/null;then
    status_message "Bad exit code from chef-server-ctl $cmd! Logs:"
    (/opt/opscode/bin/chef-server-ctl tail) & pid=$!
    pgid="`ps x -o  \"%p %r %y %x %c \" | egrep \"^[[:space:]]*$pid[[:space:]]+\" | awk '{print $2}'`"
    sleep 10 && kill -TERM -$pgid
    fail_with_message "Bad exit code from chef-server-ctl $cmd! See above logs. $pid $pgid"
  fi
}

###############################################################################
## Patch knife-windows to deal with Cygwin
patch_knife_windows()
{
  kw_version="1.8.0"

  for rubydir in $RUBY_INSTALL_DIR /opt/chef/embedded;do
    if [ -d "$rubydir/lib/ruby/gems" ];then
      # Remove gem versions other than the one we're mangling
      for gem in `find $rubydir/lib/ruby/gems -type d -name 'knife-windows-*' | grep -v "knife-windows-$kw_version" | sed 's/.*\///'`;do
        kw_badversion="`echo $gem | cut -d\- -f3`"
        status_message "Removing knife-windows $kw_badversion from $rubydir"
        $rubydir/bin/gem uninstall --force knife-windows --version $kw_badversion
      done
      knife_win_dir=`find $rubydir/lib/ruby/gems -type d -name knife-windows-$kw_version | grep -v /doc/knife-windows`

      if [ "$knife_win_dir" == "" ];then
        status_message "Installing knife-windows-$kw_version in $rubydir"
        $rubydir/bin/gem install --force knife-windows --version $kw_version
        knife_win_dir=`find $rubydir/lib/ruby/gems -type d -name knife-windows-$kw_version | grep -v /doc/knife-windows`
      fi
      if [ "`grep -i 'locate_config_value(:cygwin)' $knife_win_dir/lib/chef/knife/bootstrap_windows_base.rb`" == "" ];then
        status_message "Patching Cygwin support into knife-windows-$kw_version in $rubydir"
        cd $knife_win_dir && patch -p1 < $MU_LIBDIR/install/knife-windows-cygwin-$kw_version.patch || warning_message "Failed to patch knife-windows gem! Cygwin-based deploys of Windows hosts may not work!"
      fi
#    if [ "`grep -i '@config\[:node_ssl_verify_mode\]' $knife_win_dir/lib/chef/knife/core/windows_bootstrap_context.rb`" == "" ];then
#      status_message "Patching Chef 12 support into knife-windows-$kw_version in $rubydir"
#      cd $knife_win_dir && patch -p1 < $MU_LIBDIR/install/knife-windows-chef12-$kw_version.patch || warning_message "Failed to patch knife-windows gem! Cygwin-based deploys of Windows hosts may not work!"
#    fi
      if [ -e $rubydir ];then
        find $rubydir/lib/ruby/gems -type f -exec chmod o+r {} \;
        find $rubydir/lib/ruby/gems -type d -exec chmod o+rx {} \;
      fi
    fi
  done
  cd
}

###############################################################################
adjust_config_vars()
{
  n=1
  for v in $CONFIG_VARS;do
    var_name[$n]=$v
    var_val[$n]=${!v}
    n=$[$n +1]
  done
  last_var=$n

  print_setup_env_vars
  bypass_aws_creds=0
  while 
    read -p "Enter ${BOLD}O${NORM} to proceed with this config, or select a number to change. `echo $'\n> '`" config
  do
    echo ""
    if [ "$config" == "O" -o "$config" == "o" ];then
      validate_setup_env_vars
      if [ $validate_errs == 0 ];then
        break
      fi
    elif ! echo $config | egrep '^[0-9]{1,2}$' ; then
      warning_message "Invalid option $config"
      print_setup_env_vars
      continue
    else [ "${var_name[$config]}" != "" ] 2>/dev/null
      # Process vars with password-style reads
      if [ "${var_name[$config]}" == "MU_ADMIN_PW" ];then
        read -s -p "Enter password for the ${BOLD}mu${NORM} admin user. `echo $'\n> '`" newval
      elif [ "${var_name[$config]}" == "JENKINS_ADMIN_PW" ];then
        read -s -p "Enter password for the ${BOLD}jenkins${NORM} admin user. `echo $'\n> '`" newval
      else 

        # Process vars with normal style reads and special prompts
        case ${var_name[$config]} in
          "ADDTL_CHEF_REPOS")
            echo "Enter the Github repos from which we'll pull Chef artifacts additional to those "
            echo "from $MU_REPO. Delineate multiple repositories with spaces. Example:"
            echo "${BOLD}eGT-Labs/mu-internal.git HHS/healthdata_platform.git${NORM}"
            echo ""
            ;;&
          "MU_ADMIN_EMAIL")
            echo "Enter an email address for the internal 'mu' user."
            echo "Note that you won't be able to reuse this address for a regular user. See also:"
            echo "https://github.com/chef/chef-server/issues/59"
            ;;&
          *)
          # Everybody gets a read
            read -p "Enter new value for ${BOLD}${var_name[$config]}${NORM}. `echo $'\n> '`" newval
            ;;
        esac
      fi
      var_val[$config]=$newval
      print_setup_env_vars
    fi
  done

  n=1
  homedir="`getent passwd \"$USER\" |cut -d: -f6`"
  while [ "${var_name[$n]}" != "" ];do
    if [ "${var_name[$n]}" != "PATH" ];then
      eval "export ${var_name[$n]}=\"${var_val[$n]}\""
    fi
    # Set these in .murc too
    if [ "${var_name[$n]}" == "AWS_ACCESS" -a "${var_val[$n]}" == "" ];then
      echo "AWS_ACCESS is empty, leaving it unset" > /dev/null
    elif [ "${var_name[$n]}" == "AWS_SECRET" -a "${var_val[$n]}" == "" ];then
      echo "AWS_SECRET is empty, leaving it unset" > /dev/null
    elif [ "${var_name[$n]}" != "MU_ADMIN_PW" -a "${var_name[$n]}" != "JENKINS_ADMIN_PW" ];then
      update_murc ${var_name[$n]} "${var_val[$n]}"
    fi
    n=$[$n +1]
  done
  # Special cases- alternate env variable names for AWS credentials
  if [ "$AWS_ACCESS" != "" ];then
    update_murc AWS_ACCESS_KEY_ID $AWS_ACCESS
  fi
  if [ "$AWS_SECRET" != "" ];then
    update_murc AWS_SECRET_ACCESS_KEY $AWS_SECRET
  fi
  for v in $RO_CONFIG_VARS;do
    update_murc $v "${!v}"
  done
}

###############################################################################
create_ssh_config()
{
  mkdir -p $SSHDIR
  touch $SSHDIR/config
  chmod 600 $SSHDIR/config
#  grep "^StrictHostKeyChecking " $SSHDIR/config || echo "StrictHostKeyChecking no" >> $SSHDIR/config
}

###############################################################################
set_up_github_ssh_key()
{
  set -e
  keyname="github-key-from-mu-install.$$"
  echo "Paste a ${BOLD}private${NORM} SSH key for $1 here (^D to commit):"
  cat > $SSHDIR/$keyname
  chmod 400 $SSHDIR/$keyname
  echo "Host github.com" >> $SSHDIR/config
  echo "  User git" >> $SSHDIR/config
  echo "  IdentityFile $SSHDIR/$keyname" >> $SSHDIR/config
  echo "  StrictHostKeyChecking no" >> $SSHDIR/config
  set +e
  export keyname
}

###############################################################################
# Only use this if called right after set_up_github_ssh_key. It's not smart.
expunge_github_ssh_key(){
  keyname=$1
  head -n -3 $SSHDIR/config > $SSHDIR/config.tmp.$$
  /bin/mv -f $SSHDIR/config.tmp.$$ $SSHDIR/config
  /bin/rm -f $keyname
  unset keyname
}

fix_platform_repo_permissions()
{
  chefdir="$1"
  if [ "$chefdir" != "" ];then
    chmod go+rx $chefdir
    for subdir in applications cookbooks site_cookbooks roles environments data_bags modules Berks* README.md LICENSE.md demo;do
      if [ -e "$chefdir/$subdir" ];then
        find "$chefdir/$subdir" -type d -exec chmod go+rx {} \;
        find "$chefdir/$subdir" -type f -exec chmod go+r {} \;
      fi
    done
    for subdir in bin utils;do
      if [ -e "$chefdir/$subdir" ];then
        find "$chefdir/$subdir" -type d -exec chmod go+rx {} \;
        find "$chefdir/$subdir" -type f -exec chmod go+rx {} \;
      fi
    done
  fi
}

###############################################################################
clone_repository()
{
  set +e
  repo=$1
  clone_path=$2

  clone_ssh="git clone git@github.com:$repo $clone_path"
  # This is ugly. Adding a 30 second timeout for HTTPS clone so we don't hang if prompted for a username and/or password. 
  clone_https="timeout 30 git clone https://github.com/$repo $clone_path"
  mkdir -p $clone_path
  if [ "$(ls -A $clone_path)" ];then
    echo "$clone_path exists and is non-empty. I'm going to assume the repo has already been cloned..."
    sleep 3
  else
    mkdir -p $SSHDIR
    echo "Attempting to clone $repo without private key."
    echo $clone_https
    $clone_https 2>&1 > /dev/null
    if [ "$(ls -A $clone_path)" ];then
      echo "$clone_path exists and is not empty. I'm going to assume $repo was cloned successfully without a private key"
    else
      if [ "`grep ^github.com $SSHDIR/known_hosts 2>/dev/null`" != "" ];then
        echo "Attempting to clone $repo with existing keys..."
        echo $clone_ssh
        $clone_ssh 2>&1 > /dev/null
      fi
      if [ $? != 0 -o "`grep ^github.com $SSHDIR/known_hosts 2>/dev/null`" == "" ];then
        echo ""
        authtype=""
        echo "We'll need a key for access to ${BOLD}$repo${NORM}."
        if [ "$use_defaults" != "" ];then
          fail_with_message "In non-interactive mode, but I need Git credentials! Run without -n."
        fi
        while /bin/true ;do
          rm -rf $clone_path
          expunge_github_ssh_key $keyname
          echo ""
          set_up_github_ssh_key $repo
          echo $clone_ssh
          $clone_ssh && break
        done
      fi
    fi
  fi

  fix_platform_repo_permissions "$clone_path"
}

###############################################################################
set_hostname()
{
  if [ "$HOST_NAME" != "`hostname -s`" ];then
    hostname $HOST_NAME
    sed -i "s/^HOST_NAME=.*/HOST_NAME=$HOST_NAME/" /etc/sysconfig/network

    if [ $DIST_VERSION == 7 ];then
      hostnamectl set-hostname $HOST_NAME && systemctl restart systemd-hostnamed
    fi
  fi
  if ! grep "^$MY_PRIVATE_IP $HOST_NAME.platform-mu $HOST_NAME MU-MASTER" /etc/hosts > /dev/null;then
    sed -i "/ $HOST_NAME/d" /etc/hosts
    sed -i "/^$MY_PRIVATE_IP/d" /etc/hosts
    echo "$MY_PRIVATE_IP $HOST_NAME.platform-mu $HOST_NAME MU-MASTER" >> /etc/hosts
  fi
  if [ "$MY_PRIVATE_IP" != "$MY_PUBLIC_IP" -a "$MY_PUBLIC_IP" != "" ];then
    if ! grep "^$MY_PUBLIC_IP $HOST_NAME.platform-mu $HOST_NAME MU-MASTER" /etc/hosts > /dev/null;then
      sed -i "/ $HOST_NAME/d" /etc/hosts
      sed -i "/^$MY_PUBLIC_IP/d" /etc/hosts
      echo "$MY_PRIVATE_IP $HOST_NAME.platform-mu $HOST_NAME MU-MASTER" >> /etc/hosts
      echo "$MY_PUBLIC_IP $HOST_NAME.platform-mu $HOST_NAME MU-MASTER" >> /etc/hosts
    fi
  fi
  export HOST_NAME
}

###############################################################################
set_logbucket()
{
if [ "$LOG_BUCKET_NAME" == "" ];then
  LOG_BUCKET_NAME="mu-logs-${HOST_NAME}-${MY_INSTANCE_ID}"
fi
export LOG_BUCKET_NAME
update_murc LOG_BUCKET_NAME $LOG_BUCKET_NAME
}


###############################################################################
install_system_packages()
{
  if [ ! -f /etc/yum.repos.d/epel.repo ];then
    status_message "Installing ${BOLD}EPEL${NORM}"
    rpm -ivh ${EPEL_RPM}
  fi

  uninstall_me=""
  for pkg in $DEL_PACKAGES;do
    rpm -q $pkg 2>&1 > /dev/null && uninstall_me="${install_me} $pkg"
  done
  if [ "$uninstall_me" != "" ];then
    yum -y erase ${uninstall_me} || exit 1
  fi

  install_me=""
  for pkg in $PACKAGES;do
    rpm -q $pkg 2>&1 > /dev/null || install_me="${install_me} $pkg"
  done
  enables=""
  for r in rhui-REGION-rhel-server-releases-optional epel extras;do
    if grep $r /etc/yum.repos.d/* > /dev/null;then
      enables="${enables} --enablerepo=$r"
    fi
  done
  if [ "$install_me" != "" ];then
    status_message "Installing ${BOLD}base packages${NORM}"
    yum -y install ${enables} ${install_me} || exit 1
  fi

  # if [ $DIST_VERSION == 7 ];then
    # for pkg in $GECODE_RPMS;do
      # rpm -ivh $pkg
    # done
  # fi
}

###############################################################################
set_bash_defaults()
{
  status_message "Initializing ${BOLD}shell environment${NORM}"

  # Stange-isms, maybe these don't belong here.
  grep "alias vi=" $HOMEDIR/.bashrc > /dev/null || echo "alias vi=vim" >> $HOMEDIR/.bashrc
  grep "export EDITOR=vim" $HOMEDIR/.bashrc > /dev/null || echo "export EDITOR=vim" >> $HOMEDIR/.bashrc

  update_murc PATH "$MU_INSTALLDIR/bin:/usr/local/ruby-current/bin:\${PATH}:/opt/opscode/embedded/bin"

  grep "^source $MURC" $HOMEDIR/.bashrc > /dev/null || echo "source $MURC" >> $HOMEDIR/.bashrc

}


###############################################################################
clone_mu_repository()
{
  rpm -q git > /dev/null || yum -y install git || exit 1
  status_message "Cloning ${BOLD}$MU_REPO${NORM} to $MU_LIBDIR"
  clone_repository $MU_REPO "$MU_LIBDIR"
  status_message "Checking out $MUBRANCH"
  cd "$MU_LIBDIR" && git checkout "$MUBRANCH"

}


###############################################################################
## Go fetch a current version of Ruby.  Some of our tools will need this,
## and this isn't the same as the Ruby that is bundled with Chef, which
## will reside in its own /opt/chef sandbox and should be left unmolested.
install_ruby()
{
  if [ "$1" == "purgeold" ];then
    status_message "Purging existing ${BOLD}$RUBY_VERSION${NORM} package"
    rpm -e $RUBY_VERSION
    rm -rf $RUBY_INSTALL_DIR
  fi
  status_message "Installing ${BOLD}$RUBY_VERSION${NORM}"

  if rpm -q ruby > /dev/null ;then
    yum -y erase ruby
  fi

  if ! rpm -q $RUBY_VERSION > /dev/null ;then
    if [ "$IS_AMAZON" != "1" ];then
      yum -y install $RUBY_RPM
    else
      rpm -ivh --nodeps $RUBY_RPM # XXX hack workaround for spurious dependency
    fi
  fi
  rm -f /usr/local/ruby-current
  ln -s $RUBY_INSTALL_DIR /usr/local/ruby-current

  # Init Mu's gem library now that it has a Ruby to use.
  export USE_SYSTEM_GECODE=1
  if [ ! -f $RUBY_INSTALL_DIR/bin/bundle ];then
    set -e
    $RUBY_INSTALL_DIR/bin/gem install bundler
    cd $MU_LIBDIR/modules && $RUBY_INSTALL_DIR/bin/bundle install
    set +e
  fi
  add_chef_support_gems $RUBY_INSTALL_DIR
}

###############################################################################
## Fetch cookbooks managed by berkshelf
install_cookbooks()
{
  status_message "Installing Berkshelf cookbooks specified in $MU_LIBDIR/Berksfile"
  rm -rf $HOMEDIR/.berkshelf/cookbooks/*

  cd $MU_LIBDIR && ( /usr/local/ruby-current/bin/berks install || /usr/local/ruby-current/bin/berks update )
}

###############################################################################
## Let's use the AWS CLI tools in lieu of... well, all the other crufty
## tools we might try.
install_awscli()
{
  status_message "Installing ${BOLD}awscli${NORM}"

  test -x /usr/bin/aws || pip install awscli
  if [ ! -f $HOMEDIR/.aws/config ];then
    mkdir -p $HOMEDIR/.aws
    cat > $HOMEDIR/.aws/config <<EOF
[default]
region = $EC2_REGION
EOF
    if [ "$AWS_SECRET" != "" -a "$AWS_ACCESS" != "" ];then
      echo "aws_access_key_id = $AWS_ACCESS" >> $HOMEDIR/.aws/config
      echo "aws_secret_access_key = $AWS_SECRET" >> $HOMEDIR/.aws/config
    else
      echo "${BOLD}AWS_SECRET${NORM} or ${BOLD}AWS_ACCESS${NORM} aren't set!"
      echo "Note that ${BOLD}awscli${NORM} will not work without credentials, unless you have configured"
      echo "${BOLD}IAM Roles${NORM} to allow us to manage resources."
      echo ""
    fi
  else
    echo "Looks like /usr/bin/aws is already present."
  fi
  test -f $HOMEDIR/.aws/config && chmod 400 $HOMEDIR/.aws/config

  if ! aws ec2 describe-instances --instance-ids $MY_INSTANCE_ID >/dev/null;then
    warning_message "I can't run basic AWS commands with awscli!" "Tried: aws ec2 describe-instances --instance-ids $MY_INSTANCE_ID"
  fi
}

###############################################################################
## Create our internal-use ".platform-mu" private DNS zone
create_private_dns_zone()
{
  status_message "Creating private ${BOLD}.platform-mu${NORM} DNS zone"

  $MU_LIBDIR/bin/mu-aws-setup -d

}

###############################################################################
## Associate our preferred public IP address, if applicable.
associate_public_ip()
{
  status_message "Setting IP to ${BOLD}$CHEF_PUBLIC_IP${NORM}"

  $MU_LIBDIR/bin/mu-aws-setup -i

}

###############################################################################
configure_ec2_security_group()
{
  status_message "Detecting ${BOLD}EC2 Security Group${NORM} configuration"
  set -e
  EC2SECGROUP="`$MU_LIBDIR/bin/mu-aws-setup -s | grep 'Setting' | cut -d'(' -f2 | cut -d')' -f1`"
  set +e
  update_murc EC2SECGROUP $EC2SECGROUP
}


###############################################################################
punch_tcp_hole()
{
  port=$1
# status_message "Opening firewall for port ${BOLD}$port${NORM}"
  /sbin/iptables -nL | egrep "^ACCEPT.*dpt:$port($| )" > /dev/null || ( /sbin/iptables -I INPUT -p tcp --dport $port -j ACCEPT && service iptables save )
}

###############################################################################
## Install gems for Rubies that use Chef
add_chef_support_gems()
{
  rubydir=$1
  set -e
  $rubydir/bin/gem list | grep '^bundler' > /dev/null || $rubydir/bin/gem install bundler --no-rdoc --no-ri

  status_message "Installing support gems in $rubydir"

  cd $MU_LIBDIR/modules && $rubydir/bin/bundle install
  $rubydir/bin/gem update --system
  set +e

  find $rubydir/ -type f -exec chmod go+r {} \;
  find $rubydir/bin -type f -exec chmod go+rx {} \;
  find $rubydir/ -type d -exec chmod go+rx {} \;
}

###############################################################################
## Set up knife.rb for root
set_knife_rb()
{
  basepath="$1"
  knife_user="$2"
  url="$3"
  chef_cache="$MU_CHEF_CACHE"

  if [ "$knife_user" == "" ];then
    knife_user="mu"
  elif [ "$knife_user" != "mu" ];then
    chef_cache="`getent passwd \"$association_user\" |cut -d: -f6`/.chef"
  fi
  mkdir -p $chef_cache
  cat /dev/null > $chef_cache/knife.rb
# XXX verify_api_cert ssl_verify_mode shouldn't have to be set like this. 
# don't release with this grotesquely insecure configuration.
  cat > $chef_cache/knife.rb.tmp.$$ << EOF
log_level                :info
log_location             STDOUT
node_name                '$knife_user'
client_key               '$chef_cache/$knife_user.user.key'
validation_client_name   '$knife_user-validator'
validation_key           '$chef_cache/$knife_user.org.key'
chef_server_url "https://${CHEF_PUBLIC_IP}:7443/$basepath"
chef_server_root "https://${CHEF_PUBLIC_IP}:7443/$basepath"
syntax_check_cache_path  '$chef_cache/syntax_check_cache'
cookbook_path [ '$chef_cache/cookbooks', '$chef_cache/site_cookbooks' ]
knife[:vault_mode] = 'client'
knife[:vault_admins] = ['$knife_user']
# verify_api_cert    false
# ssl_verify_mode    :verify_none
EOF
  mv -f $chef_cache/knife.rb.tmp.$$ $chef_cache/knife.rb
}

###############################################################################
## Install the Chef Omnibus package.
install_chef()
{
  punch_tcp_hole 80
  punch_tcp_hole 443
  punch_tcp_hole 7443

  # Sometimes we get a half-deleted Chef package in our way
  if [ ! -d /opt/chef ];then
    rpm -e chef
  fi
  # Chef Server 12 inexplicably ships with old, broken versions of the
  # client. Install something sane.
  if ! rpm -q $CHEF_CLIENT_PKG > /dev/null ;then
    status_message "Installing current Chef client"
    yum -y erase chef || rpm -e chef # one of these will get it
    rm -rf /opt/chef # and stay out
    curl https://omnitruck.chef.io/install.sh > /root/chef-install.sh
    sh /root/chef-install.sh -v $CHEF_CLIENT_VERSION
  fi
  if [ -f /opt/chef/embedded/bin/gem ];then
    add_chef_support_gems /opt/chef/embedded
  fi
  port="`grep \"'ssl_port'\" /etc/opscode/chef-server.rb | awk '{print $3}'`"

  if [ "$port" == "" ];then
    port="443"
    service httpd stop # sits on 443, and Chef is stupid; disable temporarily
  fi

  set_knife_rb organizations/mu mu "https://${CHEF_PUBLIC_IP}:$port"

  # Now Chef server
  if ! rpm -q chef-server-core > /dev/null ;then
    if rpm -q chef-server > /dev/null ;then
      /opt/chef-server/bin/chef-server-ctl stop
    fi
    status_message "Installing ${BOLD}Chef Server${NORM} (listen port: ${port})"
    rpm -ivh $OPSCODE_CHEF_DL
    find /opt/opscode/embedded/lib/ruby -type f -exec chmod o+r {} \;
    find /opt/opscode/embedded/lib/ruby -type d -exec chmod o+rx {} \;
    pivotal_cfg_setup pivotal_cfg $port
    /opt/opscode/bin/chef-server-ctl reconfigure
    chef_self_test=1
  elif [ ! -f "/var/opt/opscode/nginx/ca/${CHEF_PUBLIC_IP}.crt" ];then
    status_message "Hostname or IP may have changed, reconfiguring Chef (listen port: ${port})"
    pivotal_cfg_setup pivotal_cfg $port
    /opt/opscode/bin/chef-server-ctl restart
    /opt/opscode/bin/chef-server-ctl reconfigure
    knife ssl fetch -u pivotal -k /etc/opscode/pivotal.pem -s https://${CHEF_PUBLIC_IP}:$port > /dev/null 2>&1
    rm -f /etc/chef/client.*
    knife node delete -y MU-MASTER
    knife client delete -y MU-MASTER
    chef_self_test=1
  fi
# add_chef_support_gems /opt/opscode/embedded
  pivotal_cfg_setup pivotal_cfg $port

  knife ssl fetch $pivotal_cfg > /dev/null 2>&1

  list_chef_users ext_chef_users 

  umask 0077
# if ! ( echo "$ext_chef_users" | egrep "(^| )mu( |$)" > /dev/null );then
  if  [ ! -f "$MU_DATADIR/users/mu/mu.user.key" -o ! -f "$MU_CHEF_CACHE/mu.org.key" ];then
    manage_chef_user "mu" "$MU_ADMIN_PW" "Mu Master" "$MU_ADMIN_EMAIL" "" "1" "" "1"
  fi
  mkdir -p "$MU_DATADIR/users/mu"
  echo "$MU_ADMIN_EMAIL" > "$MU_DATADIR/users/mu/email"
  echo "Mu Master" > "$MU_DATADIR/users/mu/realname"
  if [ ! -f "$MU_DATADIR/users/mu/htpasswd" -a "$MU_ADMIN_PW" != "" ];then
    # XXX this is sloppy as hell, from a security standpoint
    /usr/bin/htpasswd -c -b -m "$MU_DATADIR/users/mu/htpasswd" "mu" "$MU_ADMIN_PW"
  fi

  set_knife_rb organizations/mu mu "https://${CHEF_PUBLIC_IP}:$port"

  /opt/chef/bin/knife ssl fetch -s https://$CHEF_PUBLIC_IP:$port > /dev/null 2>&1
  umask 0022

  cur_chef="`rpm -q chef-server-core`"
  if [ "$cur_chef" != "$OPSCODE_CHEF_PKG" ];then
    status_message "Upgrading ${BOLD}Chef Server${NORM}"
    if rpm -Uvh $OPSCODE_CHEF_DL;then
      chef_self_test=1
      /opt/opscode/bin/chef-server-ctl upgrade
      find /opt/opscode/embedded/lib/ruby -type f -exec chmod o+r {} \;
      find /opt/opscode/embedded/lib/ruby -type d -exec chmod o+rx {} \;
      /opt/opscode/bin/chef-server-ctl reconfigure
#     add_chef_support_gems /opt/opscode/embedded
      $RUBY_INSTALLDIR/bin/bundle update chef
      /opt/opscode/bin/chef-server-ctl start
    else
      warning_message "Failed to upgrade to package $OPSCODE_CHEF_DL"
    fi
  fi

  export CHEF_PUBLIC_IP
  if ! ( echo $PATH | egrep ":/opt/opscode/embedded/bin(:|$)" > /dev/null );then
    export PATH="$MU_INSTALLDIR/bin:${PATH}:/opt/opscode/embedded/bin"
  fi


  mkdir -p /etc/opscode
  cat >> /etc/opscode/chef-server.rb.tmp.$$ << EOF
#
# Mu Chef Server Settings
#
server_name="$CHEF_PUBLIC_IP"

api_fqdn server_name

nginx['server_name'] = server_name
nginx['enable_non_ssl'] = false
nginx['non_ssl_port'] = 81
nginx['ssl_port'] = 7443
nginx['ssl_ciphers'] = "HIGH:MEDIUM:!LOW:!kEDH:!aNULL:!ADH:!eNULL:!EXP:!SSLv2:!SEED:!CAMELLIA:!PSK"
nginx['ssl_protocols'] = "TLSv1 TLSv1.1 TLSv1.2"
nginx['ssl_certificate'] = "$MU_SSL_CERT"
nginx['ssl_certificate_key'] = "$MU_SSL_KEY"
bookshelf['external_url'] = "https://"+server_name+":7443"
bookshelf['vip_port'] = 7443
EOF
  if [ ! -f /etc/opscode/chef-server.rb -o "`diff /etc/opscode/chef-server.rb /etc/opscode/chef-server.rb.tmp.$$`" != "" ];then
    /bin/mv -f /etc/opscode/chef-server.rb.tmp.$$ /etc/opscode/chef-server.rb
    chef_server_ctl reconfigure
  else
    /bin/rm -f /etc/opscode/chef-server.rb.tmp.$$
  fi

  # XXX workaround for vile chef bug, see:
  # https://github.com/chef/chef-server/issues/50
#  if ! grep "s3_url, \"https:\/\/${HOST_NAME}.platform-mu:7443\"" /var/opt/opscode/opscode-erchef/sys.config > /dev/null;then
#    status_message "Switching ${BOLD}Chef Server${NORM} to port ${BOLD}7443${NORM}"
#    /bin/sed -i "s/s3_url, \"https:\/\/${HOST_NAME}.platform-mu\"/s3_url, \"https:\/\/${HOST_NAME}.platform-mu:7443\"/" /var/opt/opscode/opscode-erchef/sys.config
#    chef_server_ctl restart
#  fi

  set_knife_rb organizations/mu mu "https://${CHEF_PUBLIC_IP}:7443"
  /opt/chef/bin/knife ssl fetch -s https://$CHEF_PUBLIC_IP:7443 > /dev/null 2>&1
  /opt/chef/bin/knife ssl fetch -s https://localhost:7443 > /dev/null 2>&1
  /opt/chef/bin/knife ssl fetch -s https://127.0.0.1:7443 > /dev/null 2>&1

  pivotal_cfg_setup pivotal_cfg 7443

  cat >> /etc/chef/client.rb.tmp.$$ << EOF
log_location     STDOUT
chef_server_url  "https://${CHEF_PUBLIC_IP}:7443/organizations/mu"
validation_client_name "mu-validator"
node_name "MU-MASTER"
trusted_certs_dir "/etc/chef/trusted_certs"
EOF
  if [ -f /etc/chef/client.rb -a "`diff /etc/chef/client.rb /etc/chef/client.rb.tmp.$$`" != "" ];then
    /bin/cp -f /etc/chef/client.rb.tmp.$$ /etc/chef/client.rb
  fi
  if [ -f /root/.chef/client.rb -a "`diff /root/.chef/client.rb /etc/chef/client.rb.tmp.$$`" != "" ];then
    /bin/cp -f /etc/chef/client.rb.tmp.$$ /root/.chef/client.rb
  fi
  /bin/rm -f /etc/chef/client.rb.tmp.$$ /etc/chef/validation.pem
  /sbin/service httpd start 2>&1 > /dev/null
  punch_tcp_hole 7443 # sometimes this isn't ready
  knife vault create scratchpad dummy '{ "merp":"meep" }'
  knife vault delete -y scratchpad dummy
}


upload_chef_artifacts()
{
  punch_tcp_hole 7443 # sometimes this isn't ready
  if [ "$chef_artifacts_uploaded" != "1" ];then
    if ! echo "$@" | egrep -- "-n" ;then
      rm -rf $HOMEDIR/.berkshelf
      rm -rf $HOMEDIR/.chef/cookbooks
      rm -rf $HOMEDIR/.chef/site_cookbooks
      rm -rf $MU_LIBDIR/cookbooks/cap-*
      for a in cookbooks site_bookbooks data_bags roles environments;do
        /bin/rm -rf $MU_CHEF_CACHE/$a
      done
    fi
    /opt/chef/bin/knife ssl fetch -s https://$CHEF_PUBLIC_IP > /dev/null 2>&1
    status_message "Syncing Chef artifacts to running server..."
    $MU_LIBDIR/bin/mu-upload-chef-artifacts $@
    chef_artifacts_uploaded_by_installer=1
  fi
  chef_artifacts_uploaded=1
}

###############################################################################
## Set us up to use ~/.chef, and knife accordingly.
setup_chef_cache()
{
  upload_chef_artifacts=$1
  status_message "Setting up local Chef cache in ${BOLD}$MU_CHEF_CACHE${NORM}"
  mkdir -p $MU_CHEF_CACHE
}


###############################################################################
## Get ~/.devops arranged
install_mu_executables()
{

  status_message "Installing/updating Mu executables"

#  if [ "$_me" == "mu-self-update" ];then
# XXX need to test this a different way
#    if [ "`diff $MU_LIBDIR/bin/$_me $MU_INSTALLDIR/bin/$_me`" != "" -o "`diff $MU_LIBDIR/install/mu_setup $MU_INSTALLDIR/bin/mu-configure`" != "" ];then
#      status_message "We're updating $_me, and $_me has changed." "Re-invoking as ${BOLD}$MU_LIBDIR/bin/$_me $@${NORM}"
#      /bin/cp -f $MU_LIBDIR/bin/$_me $MU_INSTALLDIR/bin/$_me
#      /bin/cp -f $MU_LIBDIR/install/mu_setup $MU_INSTALLDIR/bin/mu-configure
#      chmod 0755 $MU_INSTALLDIR/bin/$_me $MU_INSTALLDIR/bin/mu-configure
#      exec $MU_LIBDIR/bin/$_me $1 $2 $3 $4 $5 $6 $7 $8 $9
#      exit
#    fi
#  fi

  rm -rf $MU_INSTALLDIR/bin/*

  # most executables should just be symlinks
  _files=$MU_LIBDIR/bin/*
  for file in $_files;do
    f="`basename $file`"
    if [ "$f" != "mu-self-update" ];then
      ln -s $MU_LIBDIR/bin/$f $MU_INSTALLDIR/bin/$f
    fi
  done

  /bin/cp -f $MU_LIBDIR/bin/mu-self-update $MU_INSTALLDIR/bin/mu-self-update
#  /bin/cp -f $MU_LIBDIR/install/mu_setup $MU_INSTALLDIR/bin/mu-configure
  chmod 0755 $MU_INSTALLDIR/bin/mu-self-update $MU_INSTALLDIR/bin/mu-configure

  # ...and make sure the flippin' link to mu-cli-lib.rb is right.
  /bin/rm -f $MU_INSTALLDIR/bin/mu-load-config.rb
  /bin/ln -s $MU_LIBDIR/modules/mu-load-config.rb $MU_INSTALLDIR/bin/mu-load-config.rb

  chef_bin=/opt/chef/embedded/bin
  # We can get invoked before Chef is installed, so handle that gracefully
  if [ -d $chef_bin ];then
    for f in `ls -1 $chef_bin/*knife* $chef_bin/*chef* $chef_bin/*ohai*`;do
      name="`basename $f`"
      ln -s $f $MU_INSTALLDIR/bin/$name
    done
  fi

  # Same thing, but for server-only executables
  chef_bin=/opt/opscode/embedded/bin
  if [ -d $chef_bin ];then
    for f in `ls -1 $chef_bin/*knife* $chef_bin/*chef* $chef_bin/*ohai*`;do
      name="`basename $f`"
      if [ ! -h $MU_INSTALLDIR/bin/$name ];then
        ln -s $f $MU_INSTALLDIR/bin/$name
      fi
    done
  fi
  chmod 755 $MU_INSTALLDIR/bin

}

start_momma_cat()
{
  status_message "Setting up ${BOLD}mu-momma-cat${NORM}"
  punch_tcp_hole 2260
  /bin/cp -f $MU_LIBDIR/bin/mu-momma-cat /etc/init.d/
  chkconfig mu-momma-cat on
  service mu-momma-cat restart
}

###############################################################################
setup_localhost_chef_client()
{
  punch_tcp_hole 7443 # sometimes this isn't ready
  allowuser="`grep ^AllowUsers /etc/ssh/sshd_config | awk '{print $2}'`"
  if [ "$allowuser" == "" ];then
    allowuser="root"
  fi
  if [ ! -f $HOMEDIR/.ssh/id_rsa.pub ];then
    ssh-keygen -N '' -f $HOMEDIR/.ssh/id_rsa
    chmod 600 $HOMEDIR/.ssh/id_rsa
  fi
  # On CentOS 7 and the like, this is some non-root user
  ssh_homedir="`getent passwd \"$allowuser\" |cut -d: -f6`"
  mkdir -p "$ssh_homedir/.ssh/"
  pubkey="`cat $HOMEDIR/.ssh/id_rsa.pub`"
  if [ "`grep \"$pubkey\" $ssh_homedir/.ssh/authorized_keys`" == "" ];then
    echo "$pubkey" >> $ssh_homedir/.ssh/authorized_keys
  fi
  chown -R "$allowuser" "$ssh_homedir/.ssh/"
  if [ "`grep '^Host localhost' $HOMEDIR/.ssh/config`" == "" ];then
    echo "Host localhost" >> $HOMEDIR/.ssh/config
    echo "  IdentityFile $HOMEDIR/.ssh/id_rsa"  >> $HOMEDIR/.ssh/config
  fi
  if [ "`/opt/chef/bin/knife node list | grep '^CAP-MASTER$'`" == "CAP-MASTER" ];then
    warning_message "Removing old Chef node profile 'CAP-MASTER'"
    rm -f /etc/chef/client.*
    /opt/chef/bin/knife node delete -y CAP-MASTER
    /opt/chef/bin/knife client delete -y CAP-MASTER
  fi
  if [ "`/opt/chef/bin/knife node list | grep '^MU-MASTER$'`" != "MU-MASTER" ];then
    status_message "Bootstrapping localhost as Chef node 'MU-MASTER'"
    chef_artifacts_uploaded=0
    if [ "$chef_artifacts_uploaded_by_installer" != "1" ];then
      upload_chef_artifacts -n -r $MU_REPO_NAME
    fi
    mkdir -p /etc/chef
    if [ "$allowuser" == "root" -o "$allowuser" == "" ];then
      /opt/chef/bin/knife bootstrap -N MU-MASTER --no-node-verify-api-cert --node-ssl-verify-mode=none ${CHEF_PUBLIC_IP}
    else
      /opt/chef/bin/knife bootstrap -N MU-MASTER --no-node-verify-api-cert --node-ssl-verify-mode=none -x ${allowuser} --sudo ${CHEF_PUBLIC_IP}
    fi
    run_chef_client=0
  fi

  status_message "Configuring local LDAP directory"
  punch_tcp_hole 389
  punch_tcp_hole 636
  $MU_LIBDIR/install/ldap_setup.rb
  /opt/chef/bin/knife node run_list remove MU-MASTER "role[mu-master-jenkins]" > /dev/null 2>&1 # buggy prior invocations get fouled up on subsequent runs
  /opt/chef/bin/knife node run_list add MU-MASTER "role[mu-master]"
  chef_client
}

###############################################################################
configure_nagios_server()
{
  status_message "Configuring the ${BOLD}Nagios${NORM} server"
  punch_tcp_hole 8443
  if [ "`/bin/ls $MU_DATADIR/users/`" == "" ];then
    echo "${RED}Cannot enable Nagios until at least one admin user is specified.${NORM}"
    echo "${RED}Use ${BOLD}mu-user-manage${NORM}${RED} to create and manage users.${NORM}"
    return
  fi
  if [ "`grep ^nagios: /etc/passwd`" == "" -o "`pgrep -u nagios -f /usr/sbin/nagios`" == "" ];then
    # skip this if we're being called from mu-self-update and have already
    # done it
    if [ "$chef_artifacts_uploaded" != 1 ];then
	    upload_chef_artifacts -r mu
    	upload_chef_artifacts -n
    fi
    chef_client -o "recipe[mu-master::update_nagios_only]"
    run_chef_client=0
  fi
  mkdir -p /opt/mu/var/nagios_user_home
  chown nagios:nagios /opt/mu/var/nagios_user_home
  if [ "`grep ^nagios: /etc/passwd | grep /opt/mu/var/nagios_user_home`" = "" ];then
    /sbin/service nagios stop
    sleep 5
    /usr/bin/pkill -u nagios
    /usr/sbin/usermod -d /opt/mu/var/nagios_user_home nagios
    /sbin/service nagios start
  fi
  if [ -d /home/nagios ];then
    /bin/mv -f /home/nagios /home/nagios.old
    /bin/ln -s /opt/mu/var/nagios_user_home /home/nagios
  fi
}

###############################################################################
preconfigure_jenkins_artifacts()
{
  punch_tcp_hole 7443 # sometimes this isn't ready
  if [ "$JENKINS_ADMIN_PW" != "" ];then
        status_message "Configuring the ${BOLD}Jenkins${NORM} artifacts"
        punch_tcp_hole 9443
        if [ "`/bin/ls $MU_DATADIR/users/`" == "" ];then
                echo "${RED}Cannot enable Jenkins until at least one admin user is specified.${NORM}"
                echo "${RED}Use ${BOLD}mu-user-manage${NORM}${RED} to create and manage users.${NORM}"
                return
        fi
        # skip user and vault creation if we're being called from mu-self-update and have already
        # done it
        #
        if ! (knife vault show jenkins > /dev/null 2>&1) ;then
          # Create Jenkins Vault with admin and user items
          $MU_LIBDIR/install/jenkinskeys.rb
          knife vault create jenkins users "{\"mu_user_password\":\"$JENKINS_ADMIN_PW\"}" --mode client -F json -u mu --search name:MU-MASTER
          # Create the Jenkins user
        fi
        if [ ! -d /home/jenkins ];then
          $MU_LIBDIR/bin/mu-user-manage jenkins -e $JENKINS_ADMIN_EMAIL -p "$JENKINS_ADMIN_PW" -n "Jenkins Service" -s --no-scratchpad
          su - jenkins -c "ls"
        fi
  fi
  mkdir -p /home/jenkins
  chown jenkins /home/jenkins
}


generate_docs()
{
  status_message "Generating documentation"
  cd $MU_LIBDIR/modules && /usr/local/ruby-current/bin/bundle install
  /usr/local/ruby-current/bin/ruby $MU_INSTALLDIR/bin/mu-gen-docs
}

generate_ssl_certs()
{
  status_message "Managing internal SSL certificates"
  skip_chef="$1"
  mkdir -p $MU_DATADIR/ssl
  cd $MU_DATADIR/ssl
  if [ -f Mu_CA.pem ];then
    # Force us to clean up crusty old certs that we generated badly
    if ! ( /usr/bin/openssl x509 -in $MU_DATADIR/ssl/Mu_CA.pem -text -noout | grep "Subject: CN=$CHEF_PUBLIC_IP, OU=Mu Server $CHEF_PUBLIC_IP," > /dev/null );then
      /usr/bin/openssl x509 -in $MU_DATADIR/ssl/Mu_CA.pem -text -noout | grep "Subject: "
      status_message "Forcing regeneration of Mu's self-signed SSL certificate authority (didn't see ${BOLD}Subject: CN=$CHEF_PUBLIC_IP, OU=Mu Server $CHEF_PUBLIC_IP,${NORM})"
      /usr/bin/openssl x509 -in $MU_DATADIR/ssl/Mu_CA.pem -text -noout | grep "Subject: " 
      /bin/rm -f Mu_CA.*
    fi
  fi
  regen_all=0
  if [ ! -f Mu_CA.pem ];then
    regen_all=1
    status_message "Creating internal-use SSL certificate authority"
    openssl genrsa -out Mu_CA.key 4096
    chmod 400 Mu_CA.key
    openssl req -subj "/CN=$CHEF_PUBLIC_IP/OU=Mu Server $CHEF_PUBLIC_IP/O=eGlobalTech/C=US" -x509 -new -nodes -key Mu_CA.key -days 1024 -out Mu_CA.pem -sha512
    /bin/cp -f Mu_CA.pem $MU_LIBDIR/cookbooks/mu-tools/files/default/Mu_CA.pem
    if [ "$skip_chef" == "" ];then
      chef_artifacts_uploaded=0
      upload_chef_artifacts -r $MU_REPO_NAME -n -s
    fi
  elif [ ! -f $MU_LIBDIR/cookbooks/mu-tools/files/default/Mu_CA.pem ];then
    /bin/cp -f Mu_CA.pem $MU_LIBDIR/cookbooks/mu-tools/files/default/Mu_CA.pem
    if [ "$skip_chef" == "" ];then
      chef_artifacts_uploaded=0
      upload_chef_artifacts -r $MU_REPO_NAME -n -s
    fi
  fi

  # XXX should use set_serial option and maniuplate "serial"
  for cert in rsyslog mommacat ldap;do
    if [ -f $cert.crt ];then
      # Force us to clean up crusty old certs that we generated badly,
      # making sure the CA cert is bundled while we're at it.
      if ! ( grep "BEGIN CERTIFICATE" $MU_DATADIR/ssl/$cert.crt | wc -l | grep '^2$' > /dev/null );then
        status_message "Forcing regeneration of $MU_DATADIR/ssl/$cert.crt"
        /bin/rm -f $cert.crt
      elif openssl x509 -text -noout -in $MU_DATADIR/ssl/$cert.crt | grep "Signature Algorithm: sha1WithRSAEncryption" > /dev/null ;then
        status_message "Forcing regeneration of $MU_DATADIR/ssl/$cert.crt (SHA-1 signature detected)"
        /bin/rm -f $cert.crt
      fi
    fi
    if [ ! -f $cert.crt -o $regen_all == 1 ];then
      status_message "Creating self-signed $cert SSL certificate"
      openssl genrsa -out $cert.key 4096
      chmod 400 $cert.key
      openssl req -subj "/CN=$CHEF_PUBLIC_IP/OU=Mu $cert/O=eGlobalTech/C=US" -new -key $cert.key -out $cert.csr -sha512
      openssl x509 -req -in $cert.csr -CA Mu_CA.pem -CAkey Mu_CA.key -CAcreateserial -out $cert.crt -days 500 -sha512
      cat Mu_CA.pem >> $cert.crt
      if [ "$cert" == "mommacat" -a "$skip_chef" == "" ];then
        chef_server_ctl restart
        /bin/rm -f /etc/chef/trusted_certs/*.crt /root/.chef/trusted_certs/*.crt
        /opt/chef/bin/knife ssl fetch -s https://$CHEF_PUBLIC_IP > /dev/null 2>&1
        /bin/cp -f /root/.chef/trusted_certs/*.crt /etc/chef/trusted_certs/
        if (knife ssl check -c /etc/chef/client.rb | egrep "^ERROR.*certificate");then
          /opt/chef/bin/knife ssl fetch -c /etc/chef/client.rb
        fi
        if (knife ssl check | egrep "^ERROR.*certificate");then
          /opt/chef/bin/knife ssl fetch
        fi
      fi
    fi
    if [ ! -f $cert.p12 -o $regen_all == 1 ];then
      openssl pkcs12 -export -inkey $cert.key -in $cert.crt -out $cert.p12 -nodes -name "$cert" -passout pass:""
    fi
  done
  /bin/cp -f /opt/mu/var/ssl/Mu_CA.pem /etc/pki/ca-trust/source/anchors/
  /usr/bin/update-ca-trust force-enable
  /usr/bin/update-ca-trust extract
}

enable_audit_logs()
{
  status_message "Enabling Mu audit logs"
  punch_tcp_hole 10514
  set -e
  $MU_LIBDIR/bin/mu-aws-setup -l
  set +e
}

set_permissions()
{
  /bin/chmod g+rsx "$MU_DATADIR/users"
  /bin/chgrp mu-users "$MU_DATADIR/users"
  cp -a $MU_LIBDIR/extras/git-fix-permissions-hook $MU_LIBDIR/.git/hooks/post-merge
  cp -a $MU_LIBDIR/extras/git-fix-permissions-hook $MU_LIBDIR/.git/hooks/post-checkout
  cp -a $MU_LIBDIR/extras/git-fix-permissions-hook $MU_LIBDIR/.git/hooks/post-rewrite
  status_message "Setting permissions in Ruby installations and platform repos"
  test -f $MU_INSTALLDIR/etc/amazon_images.yaml && chmod 644 $MU_INSTALLDIR/etc/amazon_images.yaml
  chmod 644 $MU_INSTALLDIR/etc/mu.rc
  for extra in $ADDTL_CHEF_REPOS;do
    extra_repo_name="`echo $extra | sed 's/^.*\///' | cut -d. -f1`"
    fix_platform_repo_permissions "$MU_DATADIR/$extra_repo_name"
  done
  fix_platform_repo_permissions "$MU_LIBDIR"
  if [ "$1" != "skip_rubies" ] ;then
    /sbin/restorecon -r /home
    for rubydir in /opt/opscode/embedded /opt/chef/embedded `find /opt/rubies -maxdepth 1 -mindepth 1 -type d`;do
      find $rubydir/lib/ruby/gems -type f -exec chmod o+r {} \;
      find $rubydir/lib/ruby/gems -type d -exec chmod o+rx {} \;
    done
  fi
}

generate_repo_berksfile()
{
  repodir=$1
  cd $repodir || return
  if [ ! -f "Berksfile" ];then
    warning_message "Generating a Berksfile in ${BOLD}$repodir${NORM}"
    cat > "$repodir/Berksfile" << EOF
if !ENV.include? 'MU_DATADIR'
  if !ENV.include? 'MU_INSTALLDIR'
    raise "Can't find MU_DATADIR or MU_INSTALLDIR in my environment!"
  end

  ENV['MU_DATADIR'] = "#{ENV['MU_INSTALLDIR']}/var"
end
instance_eval(File.read(File.expand_path("#{ENV['MU_INSTALLDIR']}/lib/Berksfile", __FILE__)))
source "https://supermarket.getchef.com"
EOF
    for d in cookbooks site_cookbooks;do
      if [ -d "$repodir/$d" ];then
        cd "$repodir/$d"
        for c in `ls -1`;do
          echo "cookbook '$c', path: '$repodir/$d/$c'" >> "$repodir/Berksfile"
        done
      fi
    done
    cd "$repodir" && berks install
  fi
}

###############################################################################
###############################################################################
###############################################################################
# Main execution path begins here
###############################################################################
###############################################################################
###############################################################################


if [ "$library" != "1" ];then
  if [ "$use_defaults" == "" ];then
    adjust_config_vars
  fi
  set_path_env_vars
  set_bash_defaults
  set_hostname
  set_logbucket
  create_ssh_config
  umask 0022
  clone_mu_repository
  for extra in $ADDTL_CHEF_REPOS;do
    extra_repo_name="`echo $extra | sed 's/^.*\///' | cut -d. -f1`"
    clone_repository "$extra" "$MU_DATADIR/$extra_repo_name"
    generate_repo_berksfile "$MU_DATADIR/$extra_repo_name"
  done
  if [ "$USER" == "root" ];then
    install_system_packages
    install_ruby
    install_awscli
  fi
  install_mu_executables
  # We might disconnect right here! That's normal.
  associate_public_ip
  create_private_dns_zone
  configure_ec2_security_group
  generate_ssl_certs skip_chef
  install_chef
  patch_knife_windows
  if [ "$USER" == "root" ];then
    # set up executables again to enable Chef aliases
    install_mu_executables
    enable_audit_logs
    umask 0077
    start_momma_cat
    setup_localhost_chef_client
    generate_ssl_certs
    configure_nagios_server
    set_permissions
    preconfigure_jenkins_artifacts
  fi
  if [ "$JENKINS_ADMIN_PW" != "" ];then
    punch_tcp_hole 7443 # sometimes this isn't ready
    knife node run_list add MU-MASTER "role[mu-master-jenkins]"
    chef_client -l info
  fi
  cd
  source $MURC
  generate_docs

  # Chef's reloads of sshd don't seem to cause it to re-read its config for
  # some reason. This means regular user logins don't work on new installs
  # until it's been kicked.
  /sbin/service sshd restart

  echo ""
  echo "You MUST source all of the changes I made to your environment:"
  echo ""
  echo "${BOLD}source $MURC${NORM}"
  echo ""
  $MU_LIBDIR/bin/mu-user-manage
  echo ""
  echo "To add more users, use ${BOLD}mu-user-manage${NORM}."
  echo ""
fi
