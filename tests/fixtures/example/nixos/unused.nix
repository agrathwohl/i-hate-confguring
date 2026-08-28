{ config, ... }:

{
  # Not imported anywhere; exists to exercise dead_files detection.
  services.unused-example.enable = true;
}
