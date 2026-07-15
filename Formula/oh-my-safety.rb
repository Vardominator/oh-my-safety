class OhMySafety < Formula
  desc "macOS safety & privacy monitor: leaks, malware persistence, wallet exposure"
  homepage "https://github.com/Vardominator/oh-my-safety"
  url "https://github.com/Vardominator/oh-my-safety/archive/refs/tags/v0.2.2.tar.gz"
  # Filled in by the release workflow when the tag is pushed.
  sha256 "82a7eb98fa27d8b77fa309dc8654fd2a991794f36376d23bca6fa464bb8b37bc"
  license "MIT"
  head "https://github.com/Vardominator/oh-my-safety.git", branch: "main"

  # No dependencies on purpose: pure /bin/bash (3.2-compatible) and tools that
  # ship with macOS. "Zero dependencies" is a headline feature.

  def install
    libexec.install "bin", "lib", "config", "plugins"
    # The entry script resolves its own root by following symlinks, so a plain
    # symlink is all that's needed — no wrapper, no path rewriting.
    bin.install_symlink libexec/"bin/oh-my-safety"
    bin.install_symlink libexec/"bin/oh-my-privacy"
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
      Access — run `oh-my-safety doctor` for guidance. Everything runs
      locally; nothing is ever uploaded. See the privacy docs:
        #{opt_pkgshare}/docs/privacy.md
    EOS
  end

  test do
    assert_match "oh-my-safety v", shell_output("#{bin}/oh-my-safety version")
    assert_match "routing", shell_output("#{bin}/oh-my-safety checks")
    # A scan exits non-zero when it finds issues (normal on any real machine),
    # so just assert it runs and then that status emits valid output.
    shell_output("#{bin}/oh-my-safety scan --offline || true")
    assert_match "\"schema\"", shell_output("#{bin}/oh-my-safety status --json")
  end
end
