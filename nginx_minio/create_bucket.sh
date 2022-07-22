#!/bin/bash

mc alias set minio $HOST $USERNAME $PASSWORD
mc mb minio/static
mc policy set download minio/static

echo "finished"
tail -f /dev/null