class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.13.4"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.4/aegis-os-v0.13.4-aarch64-apple-darwin.tar.gz"
      sha256 "be81cc47c570b6da9ed91e6c60341a16b3a87ca053a25e13145f81e5f1953a80"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.4/aegis-os-v0.13.4-x86_64-apple-darwin.tar.gz"
      sha256 "a64e170336a045ae1bd5d8552670fdbf4c37cf4595a54201f878fa8003b44568"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.4/aegis-os-v0.13.4-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "35362fe4013f22755e50159a08d3fafcf351958255190bf5336e44383ac47c31"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.4/aegis-os-v0.13.4-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "8aa133e9f7f98b09d1b14ff1ab08bf1155a7c229a6bb42988fdafb848d6ce6d0"
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
