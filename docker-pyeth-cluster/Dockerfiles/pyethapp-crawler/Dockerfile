#
## Builds pyethapp from GitHub in a python 2.7.11 docker container.
## Note: base image, do not use in a production environment
##
## Build with:
#
#  docker build -t pyethapp-crawler .
#
##
## Run with:
# 
# docker run -it -p 30303:30303 -p 30303:30303/udp pyethapp-crawler
#
## Data volume
#
# To preserve data across container recreations mount a volume at /data e.g:
#
# docker run -v /somewhere/on/the/host:/data pyethapp-crawler
#

FROM python:2.7.9

RUN apt-get update
RUN apt-get install -y git-core vim

RUN pip install --upgrade pip

RUN git clone https://github.com/ethereum/pyrlp /apps/pyrlp
WORKDIR /apps/pyrlp
RUN pip install -e .

RUN git clone https://github.com/simonsk/ethereum-node-crawler /apps/ethereum-node-crawler
WORKDIR /apps/ethereum-node-crawler/pydevp2p-crawler
RUN pip install -e .

RUN git clone https://github.com/ethereum/pyethereum /apps/pyethereum
WORKDIR /apps/pyethereum
RUN pip install -e .

WORKDIR /apps/ethereum-node-crawler/pyethapp-crawler
RUN pip install -e .

# Fix debian's ridiculous gevent-breaking constant removal
# (e.g. https://github.com/hypothesis/h/issues/1704#issuecomment-63893295):
RUN sed -i 's/PROTOCOL_SSLv3/PROTOCOL_SSLv23/g' /usr/local/lib/python2.7/site-packages/gevent/ssl.py

RUN mkdir /data

EXPOSE 4000
EXPOSE 30303
EXPOSE 30303/udp

VOLUME /data

ENTRYPOINT ["/bin/bash"]
