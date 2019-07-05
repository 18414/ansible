       yum install -y wget
      wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat/jenkins.repo
      rpm --import https://pkg.jenkins.io/redhat/jenkins.io.key
      yum install jenkins  java-1.8.0-openjdk-devel git -y

