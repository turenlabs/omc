# Homebrew formula for OMC.
#
# Install (public tap):
#   brew install turenlabs/tap/omc
# or build the latest main:
#   brew install --HEAD turenlabs/tap/omc
#
# The release workflow keeps `url`/`sha256`/`version` below in sync with each
# tagged release (see scripts/update-homebrew-formula.sh). The in-repo values
# are a template: they are regenerated when the formula is published to the tap.
class Omc < Formula
  desc "Deny-by-default npm/PyPI replacement that compiles packages to verified bytecode"
  homepage "https://github.com/turenlabs/omc"
  license "Apache-2.0"
  head "https://github.com/turenlabs/omc.git", branch: "main"

  url "https://github.com/turenlabs/omc/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "894083025ac3fe9a9f838b225c10cb3f510fe11712f9806d2a23f0f908361dae"
  version "0.1.0"

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--release", "--locked", "--package", "omc-cli"

    # `omc` is the safe default that lands on PATH.
    bin.install "target/release/omc"

    # The drop-in node/npm/npx/pip/pip3/python/python3/twine shims are symlinks
    # to the single OMC binary. Installing them onto PATH would shadow the
    # system tools, so they ship under libexec and are enabled opt-in (see
    # caveats).
    (libexec/"shims").mkpath
    %w[npm npx node pip pip3 python python3 twine].each do |shim|
      (libexec/"shims"/shim).make_symlink bin/"omc"
    end

    # Recommended global policy (supply-chain freshness floor + deny-by-default).
    # Copy to ~/.omc/omc.toml to apply it under every project. See caveats.
    (share/"omc").install "examples/omc.global.toml"
  end

  def caveats
    <<~EOS
      `omc` is installed and ready to use.

      OMC also ships drop-in `node`, `npm`, `npx`, `pip`, `pip3`, `python`,
      `python3`, and `twine` shims that route through OMC's deny-by-default
      runtime. They are NOT on your PATH by default because they would shadow the
      system tools. To enable them (opt-in), prepend the shim directory:

        export PATH="#{opt_libexec}/shims:$PATH"

      Reading sensitive files (.ssh, .env, private keys, .npmrc tokens, cloud
      credentials) is denied by default even under broad grants. Grant an exact
      `fs.read:<path>` to allow one file, or pass `--allow-sensitive` to override.

      A recommended global policy (supply-chain freshness floor + deny-by-default)
      is installed at:

        #{opt_share}/omc/omc.global.toml

      Apply it under every project by copying it into place:

        mkdir -p ~/.omc && cp #{opt_share}/omc/omc.global.toml ~/.omc/omc.toml
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/omc --version")

    # Smoke-test the public surface offline: `init` scaffolds the project files.
    # (exec-cell is a dev-only command not built into release binaries.)
    # batou:ignore BATOU-RUBYAST-002 -- array-form system() (no shell), all args are literals/Homebrew testpath, not user input
    system bin/"omc", "--project-dir", testpath, "init", "--name", "smoke"
    assert_predicate testpath/"omc.toml", :exist?
  end
end
