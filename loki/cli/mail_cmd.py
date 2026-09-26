"""
loki mail — Gmail OTP integration.
loki mail setup               → save Gmail App Password
loki mail wait-otp            → wait for OTP in inbox
loki mail test                → send test email + verify connection
"""
from __future__ import annotations
import typer
from rich.console import Console

mail_app = typer.Typer(name="mail", help="Gmail OTP integration")
console = Console()


@mail_app.command("setup")
def mail_setup(
    email: str = typer.Argument(..., help="Your Gmail address"),
    app_password: str = typer.Argument(..., help="Gmail App Password (not your real password)"),
):
    """Save Gmail credentials for OTP capture."""
    from loki.core.mail.otp import save_gmail_config
    save_gmail_config(email, app_password)
    console.print(f"[green]✓ Gmail config saved for {email}[/green]")
    console.print("[dim]Generate App Password at: myaccount.google.com/apppasswords[/dim]")


@mail_app.command("wait-otp")
def mail_wait_otp(
    max_wait: int = typer.Option(90, "--timeout", "-t", help="Max wait seconds"),
    subject: str | None = typer.Option(None, "--subject", "-s", help="Filter by subject keyword"),
):
    """Wait for an OTP email and print the code."""
    from loki.core.mail.otp import wait_for_otp, load_gmail_config

    config = load_gmail_config()
    if not config:
        console.print("[red]✗ No Gmail config — run: loki mail setup your@gmail.com APP_PASSWORD[/red]")
        raise typer.Exit(1)

    console.print(f"[dim]Waiting for OTP in {config['user']}... (max {max_wait}s)[/dim]")

    try:
        otp = wait_for_otp(
            config["user"], config["app_password"],
            max_wait=max_wait,
            subject_filter=subject,
        )
        if otp:
            console.print(f"[bold green]✓ OTP: {otp}[/bold green]")
        else:
            console.print("[red]✗ No OTP received within timeout[/red]")
            raise typer.Exit(1)
    except ConnectionError as e:
        console.print(f"[red]✗ {e}[/red]")
        raise typer.Exit(1)


@mail_app.command("test")
def mail_test():
    """Test Gmail IMAP connection."""
    from loki.core.mail.otp import load_gmail_config
    import imaplib

    config = load_gmail_config()
    if not config:
        console.print("[red]✗ No Gmail config — run: loki mail setup[/red]")
        raise typer.Exit(1)

    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        mail.login(config["user"], config["app_password"])
        console.print(f"[green]✓ Connected to Gmail as {config['user']}[/green]")
        mail.logout()
    except imaplib.IMAP4.error as e:
        console.print(f"[red]✗ Login failed: {e}[/red]")
        console.print("[dim]Make sure IMAP is enabled and you're using an App Password[/dim]")
        raise typer.Exit(1)