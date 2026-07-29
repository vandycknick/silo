variable "TARGETARCH" {
  default = "amd64"
}

target "silo-release" {
  context = "."
  dockerfile = "release/Containerfile"
  platforms = ["linux/${TARGETARCH}"]
  tags = ["silo-release:linux-${TARGETARCH}"]
  args = {
    TARGETARCH = "${TARGETARCH}"
  }
}
