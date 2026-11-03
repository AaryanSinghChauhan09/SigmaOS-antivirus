use anyhow::Result;
use clap::Parser;
use antivirus::antivirus;

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    production: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = antivirus::Config { 
        production_mode: cli.production, 
        ..Default::default() 
    };
    let mut component = antivirus::new(config);
    
    component.initialize()?;
    component.start()?;
    
    println!("SigmaOS-antivirus running");
    Ok(())
}
