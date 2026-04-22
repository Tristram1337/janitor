FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash coreutils passwd acl jq e2fsprogs bsdextrautils util-linux && \
    rm -rf /var/lib/apt/lists/*

COPY target/release/janitor /usr/local/bin/janitor
COPY tests/smoke-test.sh /tests/smoke-test.sh
RUN chmod +x /tests/smoke-test.sh

ENTRYPOINT ["bash", "/tests/smoke-test.sh"]
