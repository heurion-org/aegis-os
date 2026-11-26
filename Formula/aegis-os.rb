class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.13.0"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.0/aegis-os-v0.13.0-aarch64-apple-darwin.tar.gz"
      sha256 "dc7319adf923487bb0f51cbb8062fd9a78d1f3773d49b4a6806db6eeed24792a"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.0/aegis-os-v0.13.0-x86_64-apple-darwin.tar.gz"
      sha256 "3c52e7dcb3f016f24cb751472bcbae0890020f83980691f423d6f22f3192578a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.0/aegis-os-v0.13.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "53e0fc6c7794e7f90acb43a00a2b3b5cf1c8162afc2039d7885c9caff1765308"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.13.0/aegis-os-v0.13.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d4231de16a71fd64a2e3ecee9dcebb55e901590b002dcd6f5ba3c35a9a17c85f"
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
