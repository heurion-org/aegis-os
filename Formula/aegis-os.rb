class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.14.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.14.0/aegis-os-v0.14.0-aarch64-apple-darwin.tar.gz"
      sha256 "45d249b2e10725a7a61523052b4eb1f0decb2dafbc092c1210ed96aaf7a2992f"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.14.0/aegis-os-v0.14.0-x86_64-apple-darwin.tar.gz"
      sha256 "d9827507f690a9fee465c8736cb02c0327967c6de4654a67226873754e3be34f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.14.0/aegis-os-v0.14.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "ca785e4751d52e4415d9a4844e1c36b262741f9d75150d7ba78190c924def6ae"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.14.0/aegis-os-v0.14.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "ead4be66cbe465229ceb3f8c21e3d88416ec3ac6e2295aa9f84f4d452ef22720"
    end
  end

  head do
    depends_on "rust" => :build
  end

  def install
    if File.exist?("aegis-os")
      bin.install "aegis-os"
    else
      system "cargo", "install", *std_cargo_args(path: "crates/aos-cli")
    end
    # Install short alias `aos` alongside `aegis-os`
    bin.install_symlink "aegis-os" => "aos"
  end

  def caveats
    <<~EOS
      Quickstart (`aos` is installed as a short alias for `aegis-os`):

      1. Run a 5-second local exposure & prompt-fatigue audit:
           aegis-os audit-me

      2. Launch any coding agent inside the kernel-enforced CoW sandbox:
           aegis-os run -- claude          # or: codex / opencode / agy / hermes
           aegis-os diff                   # inspect shadow changes (--json supported)
           aegis-os commit                 # SHA-256 TOCTOU-pinned promotion to host

      3. Optional: wire transparent shims & advisory integrations:
           aegis-os install --enforce      # create ~/.aegis/bin shims
           aegis-os install                # advisory hooks / MCP / rules only
    EOS
  end

  test do
    assert_match "aegis-os", shell_output("#{bin}/aegis-os --version")
    system "#{bin}/aegis-os", "install", "--home-dir", testpath, "--dry-run"
  end
end
