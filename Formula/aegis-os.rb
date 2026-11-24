class AegisOs < Formula
  desc "Kernel-enforced sandbox, CoW shadow workspace, and MCP firewall for Claude Code, Codex, OpenCode, Hermes, and AGY"
  homepage "https://github.com/heurion-org/aegis-os"
  version "0.11.1"
  license "Apache-2.0"
  head "https://github.com/heurion-org/aegis-os.git", branch: "main"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.11.1/aegis-os-v0.11.1-aarch64-apple-darwin.tar.gz"
      sha256 "0dbfb708c798f4392c3c05e6b4b6a31927ca50c909c408a5bba9813564b89394"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.11.1/aegis-os-v0.11.1-x86_64-apple-darwin.tar.gz"
      sha256 "0997af5d7e3df9dbf1d17e8ed7c746fa050863369f8805285fc74abf78834af5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.11.1/aegis-os-v0.11.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "3aaa0a9fdaac8cf986b3e8b7179e91b180adf72eb8f98bc2e3bf58ccc74884b3"
    else
      url "https://github.com/heurion-org/aegis-os/releases/download/v0.11.1/aegis-os-v0.11.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1de7489946572a76e4f481f9ae1c0691c8ea8e6fff2d6a7563f3b968abc23841"
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
