#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  clean)
    # This operation is intentionally limited to disposable hosted CI runners.
    [[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]]
    [[ -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME" && "$ANDROID_HOME" != / ]]
    sudo rm -rf -- /usr/share/dotnet /opt/ghc /usr/local/share/boost \
      /usr/local/share/powershell /usr/share/swift "$ANDROID_HOME/system-images"
    for ndk in "$ANDROID_HOME"/ndk/*; do
      if [[ -d "$ndk" && "${ndk##*/}" != 28.2.13676358 ]]; then
        sudo rm -rf -- "$ndk"
      fi
    done
    ;;
  install)
    dart pub global activate fvm 4.3.2
    export PATH="$HOME/.pub-cache/bin:$PATH"
    printf '%s\n' "$HOME/.pub-cache/bin" >> "$GITHUB_PATH"
    fvm install "$FLUTTER_VERSION"
    fvm flutter --version --machine > "$RUNNER_TEMP/relay-flutter-version.json"
    python3 -c 'import json,os; from pathlib import Path; assert json.loads((Path(os.environ["RUNNER_TEMP"])/"relay-flutter-version.json").read_text())["frameworkVersion"] == os.environ["FLUTTER_VERSION"], "Installed Flutter version mismatch"'
    fvm flutter pub get --enforce-lockfile
    ;;
  test)
    fvm flutter test --no-pub test/personal test/core/providers/clean_settings_test.dart
    fvm flutter test --no-pub --dart-define=ORONBOX_PERSONAL_BUILD=true \
      test/personal test/core/providers/clean_settings_test.dart
    ;;
  build)
    fvm flutter build apk --release --no-pub \
      --dart-define=ORONBOX_PERSONAL_BUILD=true \
      --target-platform="$PERSONAL_TARGET_PLATFORM"
    ;;
  *) echo 'Usage: ci.sh clean|install|test|build' >&2; exit 2 ;;
esac
