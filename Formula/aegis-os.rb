class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.12.3"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.3/aegis-os-v0.12.3-aarch64-apple-darwin.tar.gz"
      sha256 "085c68fd89709da0637306cf4fbea7092c759fff9f282da4c4e6d701462bd6ac"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.3/aegis-os-v0.12.3-x86_64-apple-darwin.tar.gz"
      sha256 "1f66006e2905228690fff88c03a2f286f4ed3604ad9f8ae8386fe67f12bfe2c4"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.3/aegis-os-v0.12.3-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "2ece8c396180defb30002c736c5ce50e647b8dd90bd4615c09ef79f6923f0d8b"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.12.3/aegis-os-v0.12.3-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "9e7ef9b8f1abda0d0aeb32d6779a79be201e82b29300bed77bbc78de0a9a8494"
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
