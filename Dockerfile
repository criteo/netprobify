#
# HOWTO
#
# Generate the PEX first using tox -e bundle
# the result has to be in dist/
#
# Build the image: docker build . -t netprobify
#
# Run the image: docker run -it --rm --network host -v "$PWD/config.yaml":/opt/netprobify/config.yaml --name "netprobify" netprobify
#

FROM python:3.7.1-alpine3.8

# BUILD PEX
COPY . /tmp/netprobify
WORKDIR /tmp/netprobify
RUN pip install tox
RUN /usr/local/bin/tox -e bundle
WORKDIR /opt
RUN mv /tmp/netprobify/dist/netprobify ./

# CLEANING
RUN pip uninstall -y tox six toml virtualenv filelock pluggy py
RUN rm -rf /tmp/netprobify

CMD [ "python", "/opt/netprobify" ]
