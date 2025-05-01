FROM debian:12.10-slim

RUN apt update && apt install -y libsoup2.4-1

CMD ["/bin/bash"]
