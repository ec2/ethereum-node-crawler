#!/usr/bin/env sh
PAYLOAD="{\"text\": \"<https://pypi.python.org/pypi/pyethapp|pyethapp $TRAVIS_TAG> was released on pypi!\"}"
curl -s -X POST --data-urlencode "payload=$PAYLOAD" $SLACK_WEBHOOK_URL

PAYLOAD="{\"attachments\":[{\"text\":\"[pyethapp $TRAVIS_TAG](https://pypi.org/project/pyethapp) was released on PyPI!\",\"color\":\"good\"}]}"
curl -s -X POST --data-urlencode "payload=$PAYLOAD" $ROCKETCHAT_URL
