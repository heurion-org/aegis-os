class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.13.3"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.3/aegis-os-v0.13.3-aarch64-apple-darwin.tar.gz"
      sha256 "22ef99cccd5a654b7631871bdd7c384d9f049ae0f2be06f40c1a37f98fe7fc0b"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.3/aegis-os-v0.13.3-x86_64-apple-darwin.tar.gz"
      sha256 "12a5867670917c02824263dcfc10cd003e4f35ab5a14807a9913e1fc2edeb9fb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.3/aegis-os-v0.13.3-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "7bd224621cfd2b7da857aeb9ef0aaaad95f404179ee8dff25c9ac0d9171b45e3"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.3/aegis-os-v0.13.3-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "aeb9855e30f0ad05db596f9133b08f4611e7b861e49322f2b907e9c9b5f06fbd"
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
