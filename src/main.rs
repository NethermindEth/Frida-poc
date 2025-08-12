use frida_poc::commands;

fn main() {
    // The feature flag ensures this binary is only built when needed.
    #[cfg(feature = "cli")]
    commands::run_cli();
}