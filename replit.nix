{ pkgs }: {
  deps = [
    pkgs.nodejs_20
    pkgs.nodePackages.typescript
    pkgs.sqlite
    pkgs.psmisc
    pkgs.procps
    pkgs.curl
    pkgs.git
    pkgs.which
  ];
}
