import typer

app = typer.Typer(
  name="usrctl",
  help="System administration CLI.",
  no_args_is_help=True
)

@app.callback()
def main(
  verbose: int = typer.Option(
    0,
    "-v",
    "--verbose",
    count=True,
    help="Increase the level of verbosity."
  ),
  dry_run: bool = typer.Option(
    False,
    "--dry-run",
    help="It displays actions without executing them."
  )
) -> None:
  #TODO: Conectar configuración global cuando exista la capa de ejecución.
  _ = (verbose, dry_run)

users_app = typer.Typer(help="User management commands (pending).")
groups_app = typer.Typer(help="Group management commands (pending).")
security_app = typer.Typer(help="Security commands and polices (pending).")
reports_app = typer.Typer(help="Information and reporting commands (pending).")
backup_app = typer.Typer(help="Backup and restore commands (pending).")

app.add_typer(users_app, name="users")
app.add_typer(groups_app, name="groups")
app.add_typer(security_app, name="security")
app.add_typer(reports_app, name="reports")
app.add_typer(backup_app, name="backup")

if __name__ == "__main__":
  app()
