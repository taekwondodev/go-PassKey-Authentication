variable "GO_VERSION" {
  default = "1.24.5"
}

variable "TAG" {
  default = "latest"
}

group "default" {
  targets = ["server"]
}

group "test" {
  targets = ["test-runner"]
}

target "server" {
  dockerfile = "Dockerfile"
  context = "."
  target = "server"
  args = {
    GO_VERSION = "${GO_VERSION}"
  }
  tags = [
    "passkey-auth:${TAG}",
    "passkey-auth:latest"
  ]
  platforms = ["linux/amd64", "linux/arm64"]
}

target "test-runner" {
  dockerfile = "Dockerfile"
  context = "."
  target = "test"
  args = {
    GO_VERSION = "${GO_VERSION}"
    CACHE_BUST = timestamp()
  }
  tags = ["passkey-auth:test"]
  output = ["type=docker"]
}
