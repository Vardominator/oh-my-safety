class OhMySafety < Formula
  desc "Local-first safety monitor for privacy, persistence, and exposed secrets"
  homepage "https://github.com/Vardominator/oh-my-safety"
  url "https://github.com/Vardominator/oh-my-safety/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "fc147e8ba987caba5f16ce5aa630dc439e3208851d5f884a7f1bd08d59a6ac8a"
  license "MIT"
  head do
    url "https://github.com/Vardominator/oh-my-safety.git", branch: "main"
    depends_on "go" => :build
  end

  # v0.2.x is the Bash-only compatibility release. Starting with v0.3, stable
  # source archives also build the optional pure-Go journal/scanner core.
  depends_on "go" => :build if version >= Version.new("0.3.0")

  def install
    libexec.install "bin", "lib", "config", "plugins"
    # The entry script resolves its own root by following symlinks, so a plain
    # symlink is all that's needed — no wrapper, no path rewriting.
    bin.install_symlink libexec/"bin/oh-my-safety"
    bin.install_symlink libexec/"bin/oh-my-privacy"
    if File.exist?("go.mod")
      ENV["CGO_ENABLED"] = "0"
      system "go", "build", "-trimpath", "-ldflags",
             "-X main.agentVersion=#{version}", "-o",
             libexec/"bin/oh-my-safety-agent", "./cmd/oh-my-safety-agent"
      system "go", "build", "-trimpath", "-o",
             libexec/"bin/oh-my-safety-intel", "./cmd/oh-my-safety-intel"
      bin.install_symlink libexec/"bin/oh-my-safety-agent"
      bin.install_symlink libexec/"bin/oh-my-safety-intel"
    end
    pkgshare.install "docs" if File.directory?("docs")
  end

  service do
    run [opt_bin/"oh-my-safety", "monitor", "--quiet"]
    run_type :immediate
    keep_alive true
    process_type :background
    throttle_interval 30
    log_path var/"log/oh-my-safety.log"
    error_log_path var/"log/oh-my-safety.log"
    environment_variables PATH: std_service_path_env
  end

  def caveats
    <<~EOS
      Start continuous background monitoring (launchd agent, runs at login):
        brew services start oh-my-safety

      Then, anytime:
        oh-my-safety status     # your current safety posture
        oh-my-safety scan       # run all checks now
        oh-my-safety doctor     # check setup & permissions

      Some deep checks (TCC audit, protected-folder scans) need Full Disk
      Access — run `oh-my-safety doctor` for guidance. Core scanning remains
      local; optional external adapters are off by default. See:
        #{opt_pkgshare}/docs/privacy.md
    EOS
  end

  test do
    assert_match "oh-my-safety v", shell_output("#{bin}/oh-my-safety version")
    assert_match "routing", shell_output("#{bin}/oh-my-safety checks")
    # A scan exits non-zero when it finds issues (normal on any real machine),
    # but an execution error (3+) is a distribution failure.
    shell_output("\"#{bin}/oh-my-safety\" scan --offline || [ $? -le 2 ]")
    assert_match "\"schema\"", shell_output("#{bin}/oh-my-safety status --json")
    if (bin/"oh-my-safety-agent").exist?
      assert_match "\"ready\":true",
                   shell_output("#{bin}/oh-my-safety-agent --state-db #{testpath}/journal.db")
    end
    if (bin/"oh-my-safety-intel").exist?
      assert_match "\"commands\"",
                   shell_output("#{bin}/oh-my-safety-intel help")
    end
  end
end
