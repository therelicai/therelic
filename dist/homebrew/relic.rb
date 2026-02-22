# Homebrew formula template for The Relic (relic).
#
# This file is a TEMPLATE. GoReleaser populates the sha256 checksums and
# version string automatically when running `goreleaser release`.
#
# To publish manually, copy this file to your Homebrew tap repository at:
#   Formula/relic.rb
# and fill in the version, sha256 values, and URLs from the GitHub release.
#
# See: https://docs.brew.sh/Formula-Cookbook

class Relic < Formula
  desc "Authorization and audit for autonomous AI agents"
  homepage "https://github.com/therelicai/therelic"
  license "MIT"
  version "GORELEASER_VERSION"  # replaced by goreleaser

  # macOS (Apple Silicon)
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/therelicai/therelic/releases/download/GORELEASER_VERSION/relic_GORELEASER_VERSION_Darwin_arm64.zip"
      sha256 "GORELEASER_SHA256_DARWIN_ARM64"
    else
      # macOS (Intel)
      url "https://github.com/therelicai/therelic/releases/download/GORELEASER_VERSION/relic_GORELEASER_VERSION_Darwin_x86_64.zip"
      sha256 "GORELEASER_SHA256_DARWIN_AMD64"
    end
  end

  # Linux (x86_64)
  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/therelicai/therelic/releases/download/GORELEASER_VERSION/relic_GORELEASER_VERSION_Linux_arm64.tar.gz"
      sha256 "GORELEASER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/therelicai/therelic/releases/download/GORELEASER_VERSION/relic_GORELEASER_VERSION_Linux_x86_64.tar.gz"
      sha256 "GORELEASER_SHA256_LINUX_AMD64"
    end
  end

  def install
    bin.install "relic"
  end

  def caveats
    <<~EOS
      The Relic intercepts and governs AI agent actions via MCP proxy and HTTP
      logging.

      Quick start:
        cd your-agent-project
        relic init
        relic policy init
        relic run -- <your-agent-command>

      Documentation:
        https://github.com/therelicai/therelic/blob/main/docs/ARCHITECTURE.md
    EOS
  end

  test do
    # Smoke test: --version should print and exit 0.
    assert_match version.to_s, shell_output("#{bin}/relic --version 2>&1")
    # Help should not error.
    system "#{bin}/relic", "--help"
    # `relic init` should create .tr/ in a temp dir.
    cd testpath do
      system "#{bin}/relic", "init"
      assert_predicate testpath/".tr", :directory?
      assert_predicate testpath/".tr/policy.yaml", :exist?
      assert_predicate testpath/".tr/mcp.yaml", :exist?
    end
  end
end
