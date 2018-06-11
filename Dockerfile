FROM ubuntu:18.04
RUN apt-get -y update && apt-get -y install build-essential git-core vim make gcc clang libcurl3-gnutls-dev curl wget libxml2-dev libcurl4-gnutls-dev libssh2-1-dev libz-dev libssl-dev libreadline-dev automake libtool bison manpages-dev manpages-posix-dev net-tools man-db libffi-dev libpcap-dev python3-dev python3-pip python3-venv
RUN pip3 install switchyard
WORKDIR swyard
COPY ./examples examples
CMD bash
