# A QEMU host for one Ubuntu 24.04 cloud image, for the tests tagged vm, which need a real
# kernel reboot (docs/v0.2-qualification.md). run-tests.sh supplies the cloud-init seed.
#
# The image is Ubuntu's official Noble cloud image for the host's architecture, checked
# against SHA256SUMS signed with the Ubuntu cloud image key from ubuntu-cloudimage-keyring.
FROM ubuntu:24.04
ARG RELEASE=current
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-arm qemu-system-x86 qemu-efi-aarch64 \
    qemu-utils genisoimage ca-certificates curl gpgv ubuntu-cloudimage-keyring \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /vm
RUN set -eu; \
    arch=$(dpkg --print-architecture); \
    base=https://cloud-images.ubuntu.com/noble/$RELEASE; \
    curl -fsSLO "$base/SHA256SUMS" -fsSLO "$base/SHA256SUMS.gpg"; \
    gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg SHA256SUMS.gpg SHA256SUMS; \
    curl -fsSLO "$base/noble-server-cloudimg-$arch.img"; \
    grep " \*noble-server-cloudimg-$arch.img\$" SHA256SUMS | sha256sum -c -; \
    mv "noble-server-cloudimg-$arch.img" noble.img
COPY --chmod=755 boot.sh /usr/local/bin/boot-vm
CMD ["/usr/local/bin/boot-vm"]
