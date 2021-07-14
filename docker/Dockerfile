FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive 

RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list &&\
  sed -i 's/security.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list &&\
  apt update &&\
  apt install -y apt-transport-https ca-certificates gnupg software-properties-common curl &&\
  curl -L https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null |         \
  gpg --dearmor - | \
  tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null                                     &&\
  apt-add-repository "deb https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main"      &&\
  apt update  &&\
  apt install -y gcc g++ git make cmake

#RUN mkdir /openssl                                    &&\
#  cd /openssl                                         &&\
#  git clone https://github.com/openssl/openssl.git .  &&\
#  git checkout OpenSSL_1_1_1k                         &&\
#  ./config --prefix=/usr/local/ssl                    &&\
#  make                                                &&\
#  make install 
