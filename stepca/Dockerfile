FROM smallstep/step-ca

USER root

COPY ./nsswitch.conf /etc/nsswitch.conf

RUN apk add --update bind-tools
