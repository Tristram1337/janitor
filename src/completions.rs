//! Shell completions generator (bash/zsh/fish/powershell/elvish).

use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

use crate::cli::Cli;
use crate::errors::Result;

pub fn cmd_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    let bin = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin, &mut io::stdout());
    Ok(())
}
