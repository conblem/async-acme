FROM minio/mc:RELEASE.2022-07-15T09-20-55Z

ENV HOST=http://minio:9000
ENV USERNAME=minioadmin
ENV PASSWORD=minioadmin

COPY create_bucket.sh /
RUN chmod +x create_bucket.sh
ENTRYPOINT ["/create_bucket.sh"]