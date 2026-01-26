class OhMyPrivacy < Formula
  desc "VPN privacy verification tool - checks for IP, DNS, and routing leaks"
  homepage "https://github.com/Vardominator/oh-my-privacy"
  url "https://github.com/Vardominator/oh-my-privacy/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/Vardominator/oh-my-privacy.git", branch: "main"

  depends_on "bash"
  depends_on "curl"

  def install
    # Install library files
    (lib/"oh-my-privacy").install Dir["lib/*"]

    # Install config
    (etc/"oh-my-privacy").install "config/default.yaml"

    # Install and configure the main script
    bin.install "bin/oh-my-privacy"

    # Create wrapper that sets OMP_ROOT
    (bin/"oh-my-privacy").write <<~EOS
      #!/bin/bash
      export OMP_ROOT="#{prefix}"
      exec "#{prefix}/bin/oh-my-privacy.real" "$@"
    EOS

    # Move actual script
    mv bin/"oh-my-privacy", bin/"oh-my-privacy.real"
    chmod 0755, bin/"oh-my-privacy"
    chmod 0755, bin/"oh-my-privacy.real"

    # Create config directory structure expected by the tool
    (prefix/"lib").install_symlink lib/"oh-my-privacy"
    (prefix/"config").install_symlink etc/"oh-my-privacy/default.yaml"
  end

  def post_install
    # Create user config directory
    (var/"oh-my-privacy").mkpath
  end

  def caveats
    <<~EOS
      oh-my-privacy has been installed!

      Quick start:
        oh-my-privacy --once     # Run a single privacy check
        oh-my-privacy            # Start continuous monitoring
        oh-my-privacy --help     # Show all options

      Configuration:
        Default config: #{etc}/oh-my-privacy/default.yaml
        User config: ~/.config/oh-my-privacy/config.yaml

      To create a user config:
        mkdir -p ~/.config/oh-my-privacy
        cp #{etc}/oh-my-privacy/default.yaml ~/.config/oh-my-privacy/config.yaml
    EOS
  end

  test do
    assert_match "oh-my-privacy v", shell_output("#{bin}/oh-my-privacy --version")
    assert_match "ip-address", shell_output("#{bin}/oh-my-privacy --list-checks")
  end
end
