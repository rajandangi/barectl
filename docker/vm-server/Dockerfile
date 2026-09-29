# A QEMU host for one Ubuntu cloud image, for the tests tagged vm, which need a real kernel
# reboot (docs/v0.2-qualification.md). run-tests.sh supplies the cloud-init seed.
#
# The image is Ubuntu's official server cloud image of CODENAME (noble for 24.04, resolute
# for 26.04) for the host's architecture, checked against SHA256SUMS signed with the Ubuntu
# cloud image key from ubuntu-cloudimage-keyring.
FROM ubuntu:24.04
ARG CODENAME=noble
ARG RELEASE=current
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-arm qemu-system-x86 qemu-efi-aarch64 \
    qemu-utils genisoimage ca-certificates curl gpgv ubuntu-cloudimage-keyring \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /vm
RUN set -eu; \
    arch=$(dpkg --print-architecture); \
    base=https://cloud-images.ubuntu.com/$CODENAME/$RELEASE; \
    curl -fsSLO "$base/SHA256SUMS" -fsSLO "$base/SHA256SUMS.gpg"; \
    gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg SHA256SUMS.gpg SHA256SUMS; \
    curl -fsSLO "$base/$CODENAME-server-cloudimg-$arch.img"; \
    grep " \*$CODENAME-server-cloudimg-$arch.img\$" SHA256SUMS | sha256sum -c -; \
    mv "$CODENAME-server-cloudimg-$arch.img" cloud.img
COPY --chmod=755 boot.sh /usr/local/bin/boot-vm
CMD ["/usr/local/bin/boot-vm"]
