FROM ubuntu:18.04
RUN apt-get update && apt-get install -y build-essential libssl1.0-dev libconfig-dev
ADD . /iasp
RUN make -r -R -C /iasp install-lib install-incs
RUN make -r -R -C /iasp install-app
