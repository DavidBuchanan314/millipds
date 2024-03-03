# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm

# needed for native module build (won't be needed if/when I get wheels in pypi)
RUN apt update && apt install -y gcc git

# create low-priv user (no need to mess with groups since we won't use UNIX domain sockets)
RUN adduser --system --shell /bin/false --home /opt/millipds millipds
WORKDIR /opt/millipds

# copy in the src and drop its privs
COPY . src/
RUN chown -R millipds src/

# install, under the low-priv user
USER millipds
RUN python3 -m pip install -v src/

# init the db with dev presets
RUN python3 -m millipds init millipds.test --dev

# do the thing
CMD python3 -m millipds run --listen_host=0.0.0.0 --listen_port=8123

EXPOSE 8123/tcp
