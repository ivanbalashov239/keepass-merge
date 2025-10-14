{ keepass-merge, sudo, coreutils, lib, writeShellApplication }:

writeShellApplication {
  name = "merge_keepass";
  runtimeInputs = [ keepass-merge sudo coreutils ];
  text = lib.readFile ./merge_keepass.sh;
}
