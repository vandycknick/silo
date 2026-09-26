{ lib, go }:

go.overrideAttrs (previous: {
  # Keep the pinned compiler, but use upstream runtime database locations.
  # These NixOS patches otherwise leak store paths into even CGO-free binaries.
  patches = builtins.filter (
    patch:
    let
      name = builtins.baseNameOf (toString patch);
    in
    !builtins.any (runtimePatch: lib.hasInfix runtimePatch name) [
      "iana-etc"
      "mailcap"
      "tzdata"
    ]
  ) previous.patches;

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    export GOCACHE="$TMPDIR/portable-go-cache"
    export GOENV=off GOTOOLCHAIN=local CGO_ENABLED=0
    "$out/bin/go" test -c -trimpath -ldflags="-s -w" \
      -o "$TMPDIR/portable-go.test" ${./tests/portable_go_test.go}
    if grep -aqF '/nix/store/' "$TMPDIR/portable-go.test"; then
      echo "release Go embeds Nix store paths in runtime code" >&2
      exit 1
    fi
    "$TMPDIR/portable-go.test" -test.v
    runHook postInstallCheck
  '';
})
