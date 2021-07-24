#
## Builds pyethapp from GitHub in a python 2.7.11 docker container.
## Note: base image, do not use in a production environment
##
## Build with:
#
#  docker build -t pyethcrawler .
#
##
## Run with:
# 
# docker run -it -p 30303:30303 -p 30303:30303/udp pyethcrawler
#
## Data volume
#
# To preserve data across container recreations mount a volume at /data e.g:
#
# docker run -v /somewhere/on/the/host:/data pyethcrawler
#

FROM python:2.7.11

RUN echo "mysql-server-5.5 mysql-server/root_password password  " | debconf-set-selections
RUN echo "mysql-server-5.5 mysql-server/root_password_again password  " | debconf-set-selections

RUN apt-get update
RUN apt-get install -q -y git-core vim mysql-server

RUN pip install --upgrade "pip < 21.0"
RUN pip install pymysql
RUN sh -c '/bin/echo -e "y" | apt install pandoc'

RUN pip install setuptools-markdown
RUN git clone -b v0.6.0 https://github.com/ethereum/pyrlp /apps/pyrlp
WORKDIR /apps/pyrlp
RUN pip install -e .

RUN pip install hgtools
RUN pip install pytest-runner==2.7
RUN git clone https://github.com/ethereum/pydevp2p /apps/pydevp2p
WORKDIR /apps/pydevp2p
RUN pip install -e .

RUN git clone -b master https://github.com/ethereum/pyethereum /apps/pyethereum
WORKDIR /apps/pyethereum
RUN pip install -e .

RUN git clone https://github.com/ec2/ethereum-node-crawler /apps/ethereum-node-crawler

WORKDIR /

# Fix debian's ridiculous gevent-breaking constant removal
# (e.g. https://github.com/hypothesis/h/issues/1704#issuecomment-63893295):
RUN sed -i 's/PROTOCOL_SSLv3/PROTOCOL_SSLv23/g' /usr/local/lib/python2.7/site-packages/gevent/ssl.py

RUN mkdir /data

RUN mkdir /results

EXPOSE 4000
EXPOSE 30303
EXPOSE 30303/udp

VOLUME ["/data", "/results"]
