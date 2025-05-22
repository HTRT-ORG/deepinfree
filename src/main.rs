use anyhow::Result;
use deepinfree::DeepInFreeClient;
use std::{env, io::Write};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        eprintln!(
            "Usage: {} \"your message here\" [model] [max_tokens]\nDefault model: deepseek-ai/DeepSeek-R1-Turbo\nDefault max_tokens: 8000",
            args[0]
        );
        std::process::exit(1);
    }

    let client = DeepInFreeClient::new()?;
    let message = &args[1];
    let model = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("deepseek-ai/DeepSeek-R1-Turbo");
    let max_tokens = args
        .get(3)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(8000);

    let mut stdout = std::io::stdout();
    client.send_message_streaming(message, model, max_tokens, |chunk| {
        print!("{}", chunk);
        stdout.flush()?;
        Ok(())
    })?;

    println!();
    Ok(())
}
