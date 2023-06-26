local DebianCompileJob(image, kernel_headers) = {
  "kind": "pipeline",
  "type": "docker",
  "name": image,
  "steps": [
    {
      "name": "build",
      "image": image,
      "commands": [
        "apt-get update",
        "DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install build-essential " + kernel_headers,
        "make"
      ]
    },
    {
      "name": "telegram notification for failure",
      "image": "appleboy/drone-telegram",
      "settings": {
        "token": {
          "from_secret": "tg_token"
        },
        "to": {
          "from_secret": "tg_target"
        },
        "message": "❌ Build #{{build.number}} of `{{repo.name}}`/" + image + " {{build.status}}.\n\n📝 Commit by {{commit.author}} on `{{commit.branch}}`:\n``` {{commit.message}} ```\n\n🌐 {{build.link}}"
      },
      "when": {
        "status": [
          "failure"
        ],
        "event": [
          "push"
        ]
      }
    }
  ]
};

local AlpineCompileJob(image) = {
  "kind": "pipeline",
  "type": "docker",
  "name": image,
  "steps": [
    {
      "name": "build",
      "image": image,
      "commands": [
        "apk add --no-cache build-base linux-headers",
        "make"
      ]
    },
    {
      "name": "telegram notification for failure",
      "image": "appleboy/drone-telegram",
      "settings": {
        "token": {
          "from_secret": "tg_token"
        },
        "to": {
          "from_secret": "tg_target"
        },
        "message": "❌ Build #{{build.number}} of `{{repo.name}}`/" + image + " {{build.status}}.\n\n📝 Commit by {{commit.author}} on `{{commit.branch}}`:\n``` {{commit.message}} ```\n\n🌐 {{build.link}}"
      },
      "when": {
        "status": [
          "failure"
        ],
        "event": [
          "push"
        ]
      }
    }
  ]
};

[
  {
    "kind": "secret",
    "name": "tg_token",
    "get": {
      "path": "telegram-token",
      "name": "telegram-token"
    }
  },
  {
    "kind": "secret",
    "name": "tg_target",
    "get": {
      "path": "telegram-target",
      "name": "telegram-target"
    }
  },
  DebianCompileJob('debian:buster', 'linux-headers-arm64'),
  DebianCompileJob('debian:bullseye', 'linux-headers-arm64'),
  DebianCompileJob('debian:bookworm', 'linux-headers-arm64'),
  DebianCompileJob('debian:unstable', 'linux-headers-arm64'),
  DebianCompileJob('ubuntu:focal', 'linux-headers-generic'),
  DebianCompileJob('ubuntu:jammy', 'linux-headers-generic'),
  AlpineCompileJob('alpine:edge'),
  AlpineCompileJob('alpine:latest'),
]
