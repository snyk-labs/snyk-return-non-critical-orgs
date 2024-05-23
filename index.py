from typing import Annotated
import typer
from snykApi.snykApi import *
from commands.returnSnykOrgs import *

# Create typer app
app = typer.Typer()

@app.command(help="Return organizations that do not break a policy.")
def return_snyk_orgs(group_id: Annotated[str, typer.Argument(..., help="Optional parameter for specifying an org id or a list of org ids.  Here is an example: 12345678-1234-1234-1234-123456789012,12345678-1234-1234-1234-123456789012,12345678-1234-1234-1234-123456789012")] = None):
    return_snyk_orgs_based_on_policy(group_id)

if __name__ == "__main__":
    app()