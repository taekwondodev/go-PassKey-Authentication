variable "GO_VERSION" {
  default = "1.25.0"
}

variable "TAG" {
  default = "latest"
}

group "default" {
  targets = ["server"]
}

group "test" {
  targets = ["test"]
}

target "server" {
  dockerfile = "Dockerfile"
  context = "."
  target = "server"
  args = {
    GO_VERSION = "${GO_VERSION}"
    GOEXPERIMENT = "jsonv2"
  }
  tags = [
    "passkey-auth:${TAG}",
    "passkey-auth:latest"
  ]
  platforms = ["linux/amd64", "linux/arm64"]
}

target "test" {
  dockerfile = "Dockerfile"
  context = "."
  target = "test"
  args = {
    GO_VERSION = "${GO_VERSION}"
    GOEXPERIMENT = "jsonv2"
    CACHE_BUST = timestamp()
  }
  tags = ["passkey-auth:test"]
  output = ["type=docker"]
}
