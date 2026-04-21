//! Shell completions + man page generator.

use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

use crate::cli::Cli;
use crate::errors::{PmError, Result};

pub fn cmd_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    let bin = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin, &mut io::stdout());
    Ok(())
}

pub fn cmd_man() -> Result<()> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buf: Vec<u8> = Vec::new();
    man.render(&mut buf)
        .map_err(|e| PmError::Other(format!("man render failed: {e}")))?;
    io::Write::write_all(&mut io::stdout(), &buf)
        .map_err(|e| PmError::Other(format!("man write failed: {e}")))?;
    Ok(())
}
