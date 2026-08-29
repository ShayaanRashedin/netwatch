FROM ubuntu:24.04 AS build

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        g++ \
        git \
        libsqlite3-dev \
        ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_TESTING=OFF \
    && cmake --build build --parallel \
    && DESTDIR=/stage cmake --install build

FROM ubuntu:24.04 AS runtime

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0770 /var/lib/netwatch

COPY --from=build /stage/ /

VOLUME ["/var/lib/netwatch"]
EXPOSE 8088

CMD ["netwatch", "--once"]

