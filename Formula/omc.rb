# Homebrew formula for OMC.
#
# Install:
#   brew tap turenio/omc https://github.com/turenio/omc
#   brew install omc
# or build the latest main:
#   brew install --HEAD turenio/omc/omc
#
# NOTE: turenio/omc is currently a PRIVATE repo, so Homebrew must be able to
# authenticate to fetch the source. Export a token with read access first:
#   export HOMEBREW_GITHUB_API_TOKEN=ghp_...   # (repo: read)
# Public distribution (no token) requires making the repo public or hosting the
# tarballs on a public release channel.
#
# The release workflow keeps `url`/`sha256`/`version` below in sync with each
# tagged release (see scripts/update-homebrew-formula.sh).
class Omc < Formula
  desc "Deny-by-default npm/PyPI replacement that compiles packages to verified bytecode"
  homepage "https://github.com/turenio/omc"
  license "Apache-2.0"
  head "https://github.com/turenio/omc.git", branch: "main"

  url "https://github.com/turenio/omc/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "0831bd1f2c8679ddc01f146f8738cd628e30147d4ba4893727cb7128df9badf4"
  version "0.4.0"

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--release", "--locked", "--package", "omc-cli"

    # `omc` is the safe default that lands on PATH.
    bin.install "target/release/omc"

    # The drop-in node/npm/npx/pip/pip3/python/python3/twine shims route through
    # OMC's runtime. Installing them onto PATH would shadow the system tools, so
    # they ship under libexec and are enabled opt-in (see caveats).
    %w[npm npx node pip pip3 python python3 twine].each do |shim|
      (libexec/"shims").install "target/release/#{shim}"
    end
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
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/omc --version")

    # A pure micro-package lowers, verifies, and executes in-cell.
    (testpath/"isodd.js").write("module.exports = function isOdd(n) { return n % 2 === 1; };")
    output = shell_output("#{bin}/omc --project-dir #{testpath} exec-cell #{testpath}/isodd.js --arg 7")
    assert_match "result true", output
  end
end
