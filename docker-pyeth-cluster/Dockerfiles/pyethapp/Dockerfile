# build with `docker build -t pyethapp ./pyethapp`
FROM python:2.7.9

RUN pip install --upgrade pip
RUN pip install pyethapp
ENTRYPOINT ["/usr/local/bin/pyethapp"]
