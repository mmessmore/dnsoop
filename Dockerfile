FROM golang:buster
COPY . /app
RUN apt-get update && apt-get install -y libpcap-dev
RUN cd /app && make dist/dnsnoop.linux

