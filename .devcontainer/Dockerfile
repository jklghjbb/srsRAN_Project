FROM ubuntu:22.04 as builder

# ARG version
# ARG num_procs

# ENV VERSION=$version
# ENV NUM_PROCS=$num_procs

RUN echo "Building srsRAN version $VERSION"

LABEL org.opencontainers.image.authors="Álvaro Vázquez <avrodriguez@gradiant.org>" \
      org.opencontainers.image.vendor="Gradiant" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="$version"

      RUN apt-get update && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y  \
      software-properties-common \
      git \
      build-essential \
      cmake \
      make \
      gcc \
      g++ \
      pkg-config \
      libfftw3-dev \
      libmbedtls-dev \
      libsctp-dev \
      libyaml-cpp-dev \
      libgtest-dev \
      libzmq3-dev \
      libboost-program-options-dev \
      libconfig++-dev \
      libuhd-dev \
      uhd-host \
      gettext-base \
      iproute2 \
      dnsutils \
      net-tools \
      curl \
      iptables \
      iputils-ping \
      traceroute \
      clang \
      llvm \
      libelf-dev \
      libpcap-dev \
      build-essential \
      libc6-dev-i386 \
      linux-tools-$(uname -r) \
      linux-headers-$(uname -r) \
      tcpdump \
      linux-tools-common \
      linux-tools-generic \
      m4

# RUN	cd /opt && git clone https://github.com/jklghjbb/srsRAN_Project.git
	# cd srsRAN_Project && git checkout $VERSION && \
    # mkdir build && \
    # cd build && \
    # cmake -DCMAKE_INSTALL_PREFIX=/opt/srsRAN_Project/target -DENABLE_EXPORT=ON -DENABLE_ZEROMQ=ON -DENABLE_AVX512=False ../ && \
    # make -j ${NUM_PROCS}

# RUN cd /opt/srsRAN_Project/build && make install 
