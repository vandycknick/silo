FROM debian:bookworm

RUN apt-get update && \
    apt-get install -y libguestfs-tools btrfs-progs

ENTRYPOINT ["virt-make-fs"]
