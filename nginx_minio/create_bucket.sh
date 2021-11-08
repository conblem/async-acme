#!/bin/sh

mc alias set minio http://minio:9000 minioadmin minioadmin
mc mb minio/static
mc policy set download minio/static

echo "finished"
tail -f /dev/null