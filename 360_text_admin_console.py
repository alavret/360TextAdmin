from datetime import datetime
from dotenv import load_dotenv
import requests
import logging
import json
import logging.handlers as handlers
import os
import sys
from dataclasses import dataclass
from http import HTTPStatus
import time
import argparse
import csv
import re

# Rich imports for beautiful console output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler
from rich.tree import Tree
from rich.columns import Columns
from rich.align import Align
from rich.layout import Layout
from rich.live import Live
from rich.status import Status
from rich import box
from rich.markdown import Markdown

DEFAULT_360_SCIM_API_URL = "https://{domain_id}.scim-api.passport.yandex.net/"
DEFAULT_360_API_URL = "https://api360.yandex.net"
DEFAULT_360_API_URL_V2 = "https://cloud-api.yandex.net/v1/admin/org"
ITEMS_PER_PAGE = 100
MAX_RETRIES = 3
LOG_FILE = "360_text_admin_console.log"
RETRIES_DELAY_SEC = 2
SLEEP_TIME_BETWEEN_API_CALLS = 0.5
ALL_USERS_REFRESH_IN_MINUTES = 15
# MAX value is 1000
USERS_PER_PAGE_FROM_API = 1000
# MAX value is 1000
GROUPS_PER_PAGE_FROM_API = 1000

EXIT_CODE = 1

# Initialize Rich console
console = Console()

# Setup logger with Rich handler
logger = logging.getLogger("change_scim_user_name")
logger.setLevel(logging.DEBUG)

# Rich console handler for beautiful colored output
console_handler = RichHandler(
    console=console,
    show_time=True,
    show_path=False,
    markup=True,
    rich_tracebacks=True
)
console_handler.setLevel(logging.INFO)

# File handler remains the same
file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=10* 1024 * 1024,  backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))

logger.addHandler(console_handler)
logger.addHandler(file_handler)

@dataclass
class SettingParams:
    scim_token: str
    oauth_token: str
    domain_id: int  
    org_id: int
    users_file : str
    new_login_default_format : str
    default_email_output_file : str
    default_email_input_file : str
    skip_scim_api_call : bool
    target_group : dict
    all_users : list
    all_users_get_timestamp : datetime
    forward_rules_output_file : str
    shared_mailboxes : list
    shared_mailboxes_get_timestamp : datetime
    all_groups : list
    all_groups_get_timestamp : datetime
    ignore_user_domain : bool
    users_2fa_output_file : str
    users_2fa_input_file : str

def get_settings():
    exit_flag = False
    scim_token_bad = False
    oauth_token_bad = False
    settings = SettingParams (
        scim_token = os.environ.get("SCIM_TOKEN_ARG",""),
        domain_id = os.environ.get("SCIM_DOMAIN_ID_ARG",""),
        users_file = os.environ.get("USERS_FILE_ARG"),
        new_login_default_format = os.environ.get("NEW_LOGIN_DEFAULT_FORMAT_ARG"),
        oauth_token = os.environ.get("OAUTH_TOKEN_ARG"),
        org_id = os.environ.get("ORG_ID_ARG"),
        default_email_output_file = os.environ.get("DEFAULT_EMAIL_OUTPUT_FILE_ARG", "default_email_output.csv"),
        default_email_input_file = os.environ.get("DEFAULT_EMAIL_INPUT_FILE_ARG", "default_email_input.csv"),
        forward_rules_output_file  = os.environ.get("DEFAULT_FORWARD_RULES_OUTPUT_FILE_ARG", "forward_rules_output.csv"),
        users_2fa_output_file  = os.environ.get("DEFAULT_2FA_SETTINGS_OUTPUT_FILE_ARG", "users_2fa_output.csv"),
        users_2fa_input_file  = os.environ.get("DEFAULT_2FA_SETTINGS_INPUT_FILE_ARG", "users_2fa_input.csv"),
        skip_scim_api_call = False,
        target_group = {},
        all_users = [],
        all_users_get_timestamp = datetime.now(),
        shared_mailboxes = [],
        shared_mailboxes_get_timestamp = datetime.now(),
        all_groups = [],
        all_groups_get_timestamp = datetime.now(),
        ignore_user_domain = False
    )

    if not settings.scim_token:
        logger.warning("SCIM_TOKEN_ARG is not set")
        scim_token_bad = True

    if settings.domain_id.strip() == "":
        logger.error("SCIM_DOMAIN_ID_ARG is not set")
        scim_token_bad = True

    if not settings.users_file:
        logger.error("USERS_FILE_ARG is not set")
        exit_flag = True

    if not settings.new_login_default_format:
        settings.new_login_default_format = "alias@domain.tld"

    if not settings.default_email_output_file:
        settings.default_email_output_file = "default_email_output.csv"

    if not settings.default_email_input_file:
        settings.default_email_input_file = "default_email_input.csv"

    if not settings.users_2fa_output_file:
        settings.users_2fa_output_file = "users_2fa_output.csv"
    
    if not settings.users_2fa_input_file:
        settings.users_2fa_input_file = "users_2fa_input.csv"
    
    if not settings.oauth_token:
        logger.error("OAUTH_TOKEN_ARG is not set")
        oauth_token_bad = True

    if not settings.org_id:
        logger.error("ORG_ID_ARG is not set")
        exit_flag = True

    if not (scim_token_bad or exit_flag):
        if not check_scim_token(settings.scim_token, settings.domain_id):
            logger.error("SCIM_TOKEN_ARG is not valid")
            scim_token_bad = True

    if not (oauth_token_bad or exit_flag):
        if not check_oauth_token(settings.oauth_token, settings.org_id):
            logger.error("OAUTH_TOKEN_ARG is not valid")
            oauth_token_bad = True

    if scim_token_bad:
        settings.skip_scim_api_call = True

    if oauth_token_bad:
        exit_flag = True

    if os.environ.get("IgnoreUsernameDomain", "false").lower() == "true":
        settings.ignore_user_domain = True
    
    if exit_flag:
        return None
    
    return settings

def check_scim_token(scim_token, domain_id):
    """Проверяет, что токен SCIM действителен."""
    url = DEFAULT_360_SCIM_API_URL.format(domain_id=domain_id) 
    headers = {
        "Authorization": f"Bearer {scim_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(f"{url}/v2/Users?startIndex=1&count=100", headers=headers)
    if response.status_code == HTTPStatus.OK:
        return True
    return False

def check_oauth_token(oauth_token, org_id):
    """Проверяет, что токен OAuth действителен."""
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{org_id}/users?perPage=100"
    headers = {
        "Authorization": f"OAuth {oauth_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == HTTPStatus.OK:
        return True
    return False

def parse_arguments():
    """Парсит позиционные аргументы командной строки."""
    parser = argparse.ArgumentParser(
        description="Script for changing userName attribute in Yandex 360 API SCIM or nickname attribute in Yandex 360 API.\n"
                    "Command line arguments: old new attribute [confirm]",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "old",
        help="Old userName",
        type=str,
        nargs="?",
        default=None
    )
    parser.add_argument(
        "new",
        help="New userName",
        type=str,
        nargs="?",
        default=None
    )
    parser.add_argument(
        "attribute",
        help="userName or nickname",
        choices=["userName", "username", "nickname"],
        type=str.lower,
        nargs="?",
        default=None
    )
    parser.add_argument(
        "confirm",
        help="Confirm? (yes или no)",
        choices=["yes", "no"],
        type=str.lower,
        nargs="?",
        default=None
    )
    return parser.parse_args()

def change_SCIM_username_manually(settings: "SettingParams"):
    """Интерактивный режим для ввода параметров."""
    
    console.print(Panel(
        "[bold blue]Manual SCIM Username Change[/bold blue]\n"
        "Enter old and new username values separated by space",
        title="[green]SCIM Username Management[/green]",
        border_style="blue"
    ))

    value = Prompt.ask("[bold yellow]Enter old and new value of userName, separated by space[/bold yellow]").strip()
    if not value:
        console.print("[bold red]❌ String cannot be empty.[/bold red]")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    if len(value.split()) != 2:
        console.print("[bold red]❌ There must be exactly two arguments.[/bold red]")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    old_value, new_value = value.split()
    single_mode(settings, old_value, new_value)

def single_mode(settings: "SettingParams", old_value, new_value):
    with console.status("[bold green]Loading SCIM users...", spinner="dots"):
        users = get_all_scim_users(settings)
    
    if users:
        old_user = next((item for item in users if item["userName"] == old_value.lower()), None)
        if not old_user:
            console.print(f"[bold red]❌ User {old_value} not found.[/bold red]")
            return
        new_user = next((item for item in users if item["userName"] == new_value.lower()), None)
        if new_user:
            console.print(f"[bold red]❌ User {new_value} already exists in system. Select another new value for userName.[/bold red]")
            return
        console.print(f"[green]✅ User {old_value} found. UID: {old_user['id']}. Starting change to {new_value}...[/green]")
        uid = old_user["id"]
        headers = {
                "Authorization": f"Bearer {settings.scim_token}"
                    }
        url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id)
        try:
            retries = 1
            while True:
                data = json.loads("""   { "Operations":    
                                            [
                                                {
                                                "value": "alias@domain.tld",
                                                "op": "replace",
                                                "path": "userName"
                                                }
                                            ],
                                            "schemas": [
                                                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                                            ]
                                        }""".replace("alias@domain.tld", new_value))
                
                logger.debug(f"PATCH URL: {url}/v2/Users/{uid}")
                logger.debug(f"PATCH DATA: {data}")
                response = requests.patch(f"{url}/v2/Users/{uid}", headers=headers, json=data)
                logger.debug(f"X-Request-Id: {response.headers.get("X-Request-Id","")}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        logger.error(f"Error. Patching user {old_value} to {new_value} failed.")
                        break
                else:
                    console.print(f"[bold green]🎉 Success! User {old_value} changed to {new_value}.[/bold green]")
                    break

        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
    else:
        logger.error("List of SCIM users is empty.")
        console.input("[dim]Press Enter to continue...[/dim]")
        

def main(settings: "SettingParams"):
    """Основная функция скрипта."""
    try:
        args = parse_arguments()
        old_value = args.old
        new_value = args.new
        attribute = args.attribute
        confirm = args.confirm

        # Подсчёт переданных параметров
        provided_params = sum(1 for arg in [old_value, new_value, confirm] if arg is not None)

        if settings.skip_scim_api_call:
            logger.info("No SCIM config found. Starting interactive mode.")
            interactive_mode = True
        else:
            interactive_mode = False
            # Проверка количества параметров
            if provided_params < 3:
                logger.info("There is only one command line argument, start interactive mode.")
                interactive_mode = True
            elif provided_params == 3 and old_value is not None and new_value is not None and attribute is not None:
                confirm = confirm if confirm else "no"
            elif provided_params == 4:
                pass
            else:
                logger.error("Wrong agruments count, start interactive mode.")
                interactive_mode = True

            logger.debug(f"Command line arguments: old={old_value}, new={new_value}, attribute={attribute}, confirm={confirm}")

        if interactive_mode:
            main_menu(settings)
        else:
            # Проверка подтверждения
            if confirm == "yes":
                logger.info("Confirmation received (confirm=yes), start renaming.")
                if attribute.lower() == "username":
                    single_mode(settings, old_value, new_value)
                elif attribute.lower() == "nickname":
                    change_nickname(settings, old_value, new_value)
            else:
                console.print("[bold yellow]⚠️  Need confirmation.[/bold yellow]")
                if Confirm.ask(f"[bold yellow]Confirm changing {attribute} from '{old_value}' to '{new_value}'?[/bold yellow]"):
                    if attribute.lower() == "username":
                        single_mode(settings, old_value, new_value)
                    elif attribute.lower() == "nickname":
                        change_nickname(settings, old_value, new_value)
                else:
                    console.print("[red]❌ Execution canceled.[/red]")
                    sys.exit(0)

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        sys.exit(1)

def main_menu(settings: "SettingParams"):
    while True:
        console.clear()
        
        # Create main menu panel
        menu_content = Text()
        menu_content.append("🔧 Yandex 360 Text Admin Console\n\n", style="bold blue")
        menu_content.append("1. ", style="bold cyan")
        menu_content.append("Work with SCIM userName attribute or with API 360 nickname attribute\n", style="white")
        menu_content.append("2. ", style="bold cyan")
        menu_content.append("Get user info\n", style="white")
        menu_content.append("3. ", style="bold cyan")
        menu_content.append("Get group info and manage send permission\n", style="white")
        menu_content.append("4. ", style="bold cyan")
        menu_content.append("Work with email settings\n", style="white")
        menu_content.append("5. ", style="bold cyan")
        menu_content.append("2FA settings\n\n", style="white")
        menu_content.append("0 or Ctrl+C. ", style="bold red")
        menu_content.append("Exit", style="red")

        panel = Panel(
            menu_content,
            title="[bold green]Main Menu[/bold green]",
            border_style="blue",
            padding=(1, 2)
        )
        
        console.print(panel)
        
        choice = Prompt.ask(
            "[bold yellow]Enter your choice[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5"],
            default="0"
        )

        if choice == "0":
            console.print(Panel("[bold green]Goodbye! 👋[/bold green]", border_style="green"))
            break
        elif choice == "1":
            submenu_1(settings)
        elif choice == "2":
            submenu_2(settings)
        elif choice == "3":
            submenu_3(settings)
        elif choice == "4":
            submenu_4(settings)
        elif choice == "5":
            submenu_5(settings)

def submenu_1(settings: "SettingParams"):
    while True:
        console.clear()
        
        # Create config info panel
        config_table = Table(show_header=False, box=box.SIMPLE)
        config_table.add_column("Parameter", style="cyan")
        config_table.add_column("Value", style="green")
        config_table.add_row("New loginName format:", settings.new_login_default_format)
        
        config_panel = Panel(
            config_table,
            title="[bold blue]Config Parameters[/bold blue]",
            border_style="blue"
        )
        
        # Create menu content
        menu_content = Text()
        menu_content.append("🔧 SCIM userName & API 360 nickname Management\n\n", style="bold blue")
        menu_content.append("1. ", style="bold cyan")
        menu_content.append("Set new SCIM userName format (default: alias@domain.tld)\n", style="white")
        menu_content.append("2. ", style="bold cyan")
        menu_content.append("Create SCIM data file for modification in next step\n", style="white")
        menu_content.append("3. ", style="bold cyan")
        menu_content.append("Use users file to change SCIM userName of users\n", style="white")
        menu_content.append("4. ", style="bold cyan")
        menu_content.append("Enter old and new value of userName manually and confirm renaming\n", style="white")
        menu_content.append("5. ", style="bold cyan")
        menu_content.append("Change nickname of single user\n", style="white")
        menu_content.append("6. ", style="bold cyan")
        menu_content.append("Check alias for user\n", style="white")
        menu_content.append("7. ", style="bold cyan")
        menu_content.append("Show user attributes and save their to file\n", style="white")
        menu_content.append("8. ", style="bold cyan")
        menu_content.append("Download all users to file (SCIM и API) protocols\n\n", style="white")
        menu_content.append("0 or empty string. ", style="bold red")
        menu_content.append("Back to main menu", style="red")

        menu_panel = Panel(
            menu_content,
            title="[bold green]SCIM & Nickname Management[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        
        console.print(config_panel)
        console.print(menu_panel)
        
        choice = Prompt.ask(
            "[bold yellow]Enter your choice[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"],
            default="0"
        )

        if choice == "0":
            break
        elif choice == "1":
            set_new_loginName_format(settings)
        elif choice == "2":
            if settings.skip_scim_api_call:
                console.print("[bold red]⚠️  No SCIM config found. Skip action.[/bold red]")
                console.input("[dim]Press Enter to continue...[/dim]")
            else:
                create_SCIM_userName_file(settings)
        elif choice == "3":
            if settings.skip_scim_api_call:
                console.print("[bold red]⚠️  No SCIM config found. Skip action.[/bold red]")
                console.input("[dim]Press Enter to continue...[/dim]")
            else:
                update_users_from_SCIM_userName_file(settings)
        elif choice == "4":
            if settings.skip_scim_api_call:
                console.print("[bold red]⚠️  No SCIM config found. Skip action.[/bold red]")
                console.input("[dim]Press Enter to continue...[/dim]")
            else:
                change_SCIM_username_manually(settings)
        elif choice == "5":
            change_nickname_prompt(settings)
        elif choice == "6":
            check_alias_prompt(settings)
        elif choice == "7":
            show_user_attributes(settings)
        elif choice == "8":
            download_users_attrib_to_file(settings)
    return

def submenu_2(settings: "SettingParams"):
    while True:
        console.clear()
        
        # Create menu content
        menu_content = Text()
        menu_content.append("👤 User Information Management\n\n", style="bold blue")
        menu_content.append("1. ", style="bold cyan")
        menu_content.append("Check alias for user\n", style="white")
        menu_content.append("2. ", style="bold cyan")
        menu_content.append("Download all users to file (SCIM и API) protocols\n", style="white")
        menu_content.append("3. ", style="bold cyan")
        menu_content.append("Show user attributes and save their to file\n\n", style="white")
        menu_content.append("0 or empty string. ", style="bold red")
        menu_content.append("Back to main menu", style="red")

        menu_panel = Panel(
            menu_content,
            title="[bold green]Get User Info[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        
        console.print(menu_panel)
        
        choice = Prompt.ask(
            "[bold yellow]Enter your choice[/bold yellow]",
            choices=["0", "1", "2", "3"],
            default="0"
        )

        if choice == "0":
            break
        elif choice == "1":
            check_alias_prompt(settings)
        elif choice == "2":
            download_users_attrib_to_file(settings)
        elif choice == "3":
            show_user_attributes(settings)

    return

def submenu_3(settings: "SettingParams"):
    while True:
        console.clear()
        
        # Create menu content
        menu_content = Text()
        menu_content.append("👥 Group Information & Permissions Management\n\n", style="bold blue")
        menu_content.append("1. ", style="bold cyan")
        menu_content.append("Show group attributes and save their to file\n", style="white")
        menu_content.append("2. ", style="bold cyan")
        menu_content.append("Show approve senders for group\n", style="white")
        menu_content.append("3. ", style="bold cyan")
        menu_content.append("Manage approve senders for group\n\n", style="white")
        menu_content.append("0 or empty string. ", style="bold red")
        menu_content.append("Back to main menu", style="red")

        menu_panel = Panel(
            menu_content,
            title="[bold green]Get Group Info[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        
        console.print(menu_panel)
        
        choice = Prompt.ask(
            "[bold yellow]Enter your choice[/bold yellow]",
            choices=["0", "1", "2", "3"],
            default="0"
        )

        if choice == "0":
            break
        elif choice == "1":
            save_group_data_prompt(settings)
        elif choice == "2":
            show_mailing_list_permissions(settings)
        elif choice == "3":
            subsubmenu_30(settings)

    return

def submenu_4(settings: "SettingParams"):
    while True:
        console.clear()
        
        # Create menu content
        menu_content = Text()
        menu_content.append("📧 Email Settings Management\n\n", style="bold blue")
        menu_content.append("1. ", style="bold cyan")
        menu_content.append("Create file for default email modification\n", style="white")
        menu_content.append("2. ", style="bold cyan")
        menu_content.append("Update default email from file\n", style="white")
        menu_content.append("3. ", style="bold cyan")
        menu_content.append("Get forward rules for single user\n", style="white")
        menu_content.append("4. ", style="bold cyan")
        menu_content.append("Download forward rules for all users\n", style="white")
        menu_content.append("5. ", style="bold cyan")
        menu_content.append("Clear forward rules for users\n\n", style="white")
        menu_content.append("0 or empty string. ", style="bold red")
        menu_content.append("Back to main menu", style="red")

        menu_panel = Panel(
            menu_content,
            title="[bold green]Work with Email Settings[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        
        console.print(menu_panel)
        
        choice = Prompt.ask(
            "[bold yellow]Enter your choice[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5"],
            default="0"
        )

        if choice == "0":
            break
        elif choice == "1":
            default_email_create_file(settings)
        elif choice == "2":
            default_email_update_from_file(settings)
        elif choice == "3":
            forward_rules_get_for_user(settings)
        elif choice == "4":
            forward_rules_download_for_all_users(settings)
        elif choice == "5":
            forward_rules_clear_for_user(settings)

    return

def submenu_5(settings: "SettingParams"):
    while True:
        console.clear()
        
        # Create menu content
        menu_content = Text()
        menu_content.append("🔐 2FA Settings Management\n\n", style="bold blue")
        menu_content.append("1. ", style="bold cyan")
        menu_content.append("Download 2FA settings for users\n", style="white")
        menu_content.append("2. ", style="bold cyan")
        menu_content.append("Get 2FA settings for single user\n", style="white")
        menu_content.append("3. ", style="bold cyan")
        menu_content.append("Reset personal phone for single user\n", style="white")
        menu_content.append("4. ", style="bold cyan")
        menu_content.append("Logout single user\n", style="white")
        menu_content.append("5. ", style="bold cyan")
        menu_content.append("Logout users from file\n", style="white")
        menu_content.append("6. ", style="bold cyan")
        menu_content.append("Logout users with 2fa set and no security phone configured\n\n", style="white")
        menu_content.append("0 or empty string. ", style="bold red")
        menu_content.append("Back to main menu", style="red")

        menu_panel = Panel(
            menu_content,
            title="[bold green]2FA Settings[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        
        console.print(menu_panel)
        
        choice = Prompt.ask(
            "[bold yellow]Enter your choice[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5", "6"],
            default="0"
        )

        if choice == "0":
            break
        elif choice == "1":
            mfa_download_settings(settings)
        elif choice == "2":
            mfa_prompt_settings_for_user(settings)
        elif choice == "3":
            mfa_reset_personal_phone_prompt(settings)
        elif choice == "4":
            mfa_logout_single_user_prompt(settings)
        elif choice == "5":
            mfa_logout_users_from_file(settings)
        elif choice == "6":
            mfa_logout_users_with_no_phone(settings)

    return

def subsubmenu_30(settings: "SettingParams"):
    while True:
        console.clear()
        
        # Create current params table
        params_table = Table(show_header=False, box=box.SIMPLE)
        params_table.add_column("Parameter", style="cyan")
        params_table.add_column("Value", style="green")
        params_table.add_row("Target group Name:", settings.target_group.get("name", "[red]Not set[/red]"))
        params_table.add_row("Target group ID:", str(settings.target_group.get("id", "[red]Not set[/red]")))
        params_table.add_row("Target group emailId:", str(settings.target_group.get("emailId", "[red]Not set[/red]")))
        
        params_panel = Panel(
            params_table,
            title="[bold blue]Current Parameters[/bold blue]",
            border_style="blue"
        )
        
        # Create menu content
        menu_content = Text()
        menu_content.append("🔐 Group Send Permissions Management\n\n", style="bold blue")
        menu_content.append("1. ", style="bold cyan")
        menu_content.append("Set target group\n", style="white")
        menu_content.append("2. ", style="bold cyan")
        menu_content.append("Add users to allow list\n", style="white")
        menu_content.append("3. ", style="bold cyan")
        menu_content.append("Remove users from allow list\n", style="white")
        menu_content.append("4. ", style="bold cyan")
        menu_content.append("Grant all users send permission\n", style="white")
        menu_content.append("5. ", style="bold cyan")
        menu_content.append("Add/Remove shared mailbox to allow list\n\n", style="white")
        menu_content.append("0 or empty string. ", style="bold red")
        menu_content.append("Back to main menu", style="red")

        menu_panel = Panel(
            menu_content,
            title="[bold green]Manage Group Send Permissions[/bold green]",
            border_style="green",
            padding=(1, 2)
        )
        
        console.print(params_panel)
        console.print(menu_panel)
        
        choice = Prompt.ask(
            "[bold yellow]Enter your choice[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5"],
            default="0"
        )

        if choice == "0":
            break
        elif choice == "1":
            send_perm_set_target_group(settings)
        elif choice == "2":
            send_perm_add_users_to_allow_list_prompt(settings)
        elif choice == "3":
            send_perm_remove_users_from_allow_list(settings)
        elif choice == "4":
            send_perm_grand_all_users(settings)
        elif choice == "5":
            send_perm_shared_mailbox(settings)

    return

def set_new_loginName_format(settings: "SettingParams"):
    console.print(Panel(
        "[bold blue]Set New Login Name Format[/bold blue]\n"
        f"Current format: [green]{settings.new_login_default_format}[/green]\n"
        "Default format: [cyan]alias@domain.tld[/cyan]",
        title="[green]Login Format Configuration[/green]",
        border_style="blue"
    ))
    
    answer = Prompt.ask(
        "[bold yellow]Enter format of new userLogin name[/bold yellow]",
        default=settings.new_login_default_format
    )
    
    if answer.strip() == "":
        settings.new_login_default_format = "alias@domain.tld"
        console.print("[green]✅ Format set to default: alias@domain.tld[/green]")
    else:
        settings.new_login_default_format = answer.strip()
        console.print(f"[green]✅ Format set to: {settings.new_login_default_format}[/green]")
    
    console.input("[dim]Press Enter to continue...[/dim]")
    return settings

def get_all_api360_users(settings: "SettingParams", force = False):
    if not force:
        logger.info("Getting all users of the organisation from cache...")

    if not settings.all_users or force or (datetime.now() - settings.all_users_get_timestamp).total_seconds() > ALL_USERS_REFRESH_IN_MINUTES * 60:
        logger.info("Getting all users of the organisation from API...")
        settings.all_users = get_all_api360_users_from_api(settings)
        settings.all_users_get_timestamp = datetime.now()
    return settings.all_users

def get_all_shared_mailboxes(settings: "SettingParams", force = False):
    if not force:
        logger.info("Getting all shared mailboxes of the organisation from cache...")

    if not settings.shared_mailboxes or force:
        logger.info("Getting all shared mailboxes of the organisation from API...")

        result, settings.shared_mailboxes = get_shared_mailbox_detail(settings)
        if not result:
            logger.error("Can not get shared mailboxes data from Y360 API.")
        settings.shared_mailboxes_get_timestamp = datetime.now()
    else:
        if (datetime.now() - settings.shared_mailboxes_get_timestamp).total_seconds() > ALL_USERS_REFRESH_IN_MINUTES * 60:
            logger.info("Getting all shared mailboxes of the organisation from API...")
            result, settings.shared_mailboxes = get_shared_mailbox_detail(settings)
            if not result:
                logger.error("Can not get shared mailboxes data from Y360 API.")
            settings.shared_mailboxes_get_timestamp = datetime.now()
    return settings.shared_mailboxes

def get_all_groups(settings: "SettingParams", force = False):
    if not force:
        logger.info("Getting all groups of the organisation from cache...")

    if not settings.all_groups or force:
        logger.info("Getting all all groups of the organisation from API...")
        settings.all_groups = get_all_groups_from_api360(settings)
        settings.all_groups_get_timestamp = datetime.now()
    else:
        if (datetime.now() - settings.all_groups_get_timestamp).total_seconds() > ALL_USERS_REFRESH_IN_MINUTES * 60:
            logger.info("Getting all all groups of the organisation from API...")
            settings.all_groups = get_all_groups_from_api360(settings)
            settings.all_groups_get_timestamp = datetime.now()
    return settings.all_groups

def http_get_request(url, headers):
    try:
        retries = 1
        while True:
            logger.debug(f"GET URL - {url}")
            response = requests.get(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ERROR !!! during GET request url - {url}: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"!!! Error !!! during GET request url - {url}.")
                    break
            else:
                break

    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    return response

def get_all_api360_users_from_api(settings: "SettingParams"):
    logger.info("Getting all users of the organisation...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    has_errors = False
    users = []
    current_page = 1
    last_page = 1
    while current_page <= last_page:
        params = {'page': current_page, 'perPage': USERS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                logger.debug(f"GET URL - {url}")
                response = requests.get(url, headers=headers, params=params)
                logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"!!! ERROR !!! during GET request url - {url}: {response.status_code}. Error message: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        has_errors = True
                        break
                else:
                    for user in response.json()['users']:
                        if not user.get('isRobot') and int(user["id"]) >= 1130000000000000:
                            users.append(user)
                    logger.debug(f"Get {len(response.json()['users'])} users from page {current_page} (total {last_page} page(s)).")
                    current_page += 1
                    last_page = response.json()['pages']
                    break

        except requests.exceptions.RequestException as e:
            logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            has_errors = True
            break

        if has_errors:
            break

    if has_errors:
        print("There are some error during GET requests. Return empty user list.")
        return []
    
    return users

def get_all_groups_from_api360(settings: "SettingParams"):

    logger.info("Getting all groups of the organisation...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    has_errors = False
    groups = []
    current_page = 1
    last_page = 1
    while current_page <= last_page:
        params = {'page': current_page, 'perPage': GROUPS_PER_PAGE_FROM_API}
        try:
            retries = 1
            while True:
                logger.debug(f"GET URL - {url}")
                response = requests.get(url, headers=headers, params=params)
                logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"!!! ERROR !!! during GET request url - {url}: {response.status_code}. Error message: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        has_errors = True
                        break
                else:
                    groups.extend(response.json()['groups'])
                    logger.debug(f"Get {len(response.json()['groups'])} groups from page {current_page} (total {last_page} page(s)).")
                    current_page += 1
                    last_page = response.json()['pages']
                    break

        except requests.exceptions.RequestException as e:
            logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            has_errors = True
            break

        if has_errors:
            break

    if has_errors:
        logger.error("There are some error during GET requests. Return empty groups list.")
        return []
    
    return groups

def find_group_by_param(groups: list, search_string: str, search_type: str ):
    """Find group by exact alias match, email prefix match, or partial group name match"""
    logger.debug(f"Finding group by search string {search_string}...")
    result = []  # noqa: F811
    for group in groups:
        # Check aliases
        if search_type == 'alias':
            if search_string in group.get('aliases', []):
                if group not in result:
                    result.append(group)
            # Check email prefix (part before @)
            email = group.get('email', '')
            if email and '@' in email:
                email_prefix = email.split('@')[0]
                if email_prefix == search_string:
                    if group not in result:
                        result.append(group)
            # Check group name (partial match, case-insensitive)
            group_name = group.get('name', '')
            if search_string.lower() in group_name.lower():
                if group not in result:
                    result.append(group)
        elif search_type == "id":
            if search_string == str(group.get('id', '')):
                if group not in result:
                    result.append(group)
        elif search_type == "uid":
            if search_string == group.get('emailId', ''):
                if group not in result:
                    result.append(group)
    return result

def get_default_email(settings: "SettingParams", userId: str):
    logger.debug(f"Getting default email for user {userId}...")
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mail/users/{userId}/settings/sender_info"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    data = {}
    try:
        retries = 1
        while True:
            logger.debug(f"GET url - {url}")
            response = requests.get(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request for user {userId}: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Getting default email data for user {userId} failed.")
                    break
            else:
                data = response.json()
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    return data

def get_all_scim_users(settings: "SettingParams"):
    
    if settings.skip_scim_api_call:
        logger.info("No SCIM config found. Skip getting all users of the organisation from SCIM action.")
        return []
    
    logger.info("Getting all users of the organisation from SCIM...")
    users = []
    headers = {
        "Authorization": f"Bearer {settings.scim_token}"
    }
    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id)
    startIndex = 1
    items = ITEMS_PER_PAGE
    try:
        retries = 1
        while True:  
            logger.debug(f"GET url - {url}")         
            response = requests.get(f"{url}/v2/Users?startIndex={startIndex}&count={items}", headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Forcing exit without getting data.")
                    return
            else:
                retries = 1
                temp_list = response.json()["Resources"]
                logger.debug(f'Received {len(temp_list)} records.')
                users.extend(temp_list)

                if int(response.json()["startIndex"]) + int(response.json()["itemsPerPage"]) > int(response.json()["totalResults"]) + 1:
                    break
                else:
                    startIndex = int(response.json()["startIndex"]) + int(response.json()["itemsPerPage"])

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    
    if settings.ignore_user_domain:
        for user in users:
            user["userName"] = user["userName"].split("@")[0]

    return users

def change_nickname_prompt(settings: "SettingParams"):
    """
    Interactive prompt for changing user nicknames.
    
    Continuously prompts the user to enter old and new nickname values separated by space.
    Validates input to ensure exactly two space-separated values are provided.
    Calls change_nickname function with the provided values.
    Exits when user enters an empty string.
    
    Args:
        settings (SettingParams): Configuration settings containing API tokens and organization details.
        
    Returns:
        None
    """
    console.print(Panel(
        "[bold blue]Change User Nickname[/bold blue]\n"
        "Enter old and new nickname values separated by space\n"
        "[dim]Example: oldnick newnick[/dim]",
        title="[green]Nickname Management[/green]",
        border_style="blue"
    ))
    
    while True:
        data = Prompt.ask(
            "[bold yellow]Enter old value and new value of nickname separated by space[/bold yellow]",
            default=""
        )
        
        if len(data.strip()) == 0:
            break
        elif len(data.split()) != 2:
            console.print("[bold red]❌ Invalid input. Please enter old value and new value separated by space.[/bold red]")
            console.input("[dim]Press Enter to continue...[/dim]")
        else:
            old_value, new_value = data.split()
            #with console.status(f"[bold green]Changing nickname from '{old_value}' to '{new_value}'...", spinner="dots"):
            change_nickname(settings, old_value, new_value)
            #console.input("[dim]Press Enter to continue...[/dim]")
    return

def check_alias_prompt(settings: "SettingParams"):
    console.print(Panel(
        "[bold blue]Check Alias Availability[/bold blue]\n"
        "Enter alias names to check if they are already in use",
        title="[green]Alias Checker[/green]",
        border_style="blue"
    ))
    
    while True:
        data = Prompt.ask(
            "[bold yellow]Enter alias (without domain) to check[/bold yellow]",
            default=""
        )
        
        if len(data.strip()) == 0:
            break
        elif len(data.split("@")) == 2:
            data = data.split("@")[0]

        check_alias(settings, data.lower())
        
    return

def check_alias(settings: "SettingParams", alias: str):
    console.print(f"[bold blue]🔍 Checking alias: [cyan]{alias}[/cyan][/bold blue]")
    
    users = get_all_api360_users(settings)
    if not users:
        console.print("[bold red]❌ No users found.[/bold red]")
        return
    
    console.print(f"[green]✅ Found {len(users)} users to check[/green]")
    
    # Create results table
    results_table = Table(title=f"Alias Check Results for '{alias}'")
    results_table.add_column("Type", style="cyan")
    results_table.add_column("User", style="green")
    results_table.add_column("ID", style="yellow")
    results_table.add_column("Display Name", style="white")
    
    found_conflicts = False
    
    for user in users:
        if alias == user['nickname']:
            results_table.add_row(
                "Nickname",
                user['nickname'],
                user['id'],
                user.get('displayName', '')
            )
            found_conflicts = True
            
        if alias in user['aliases']:
            results_table.add_row(
                "Alias",
                user['nickname'],
                user['id'],
                user.get('displayName', '')
            )
            found_conflicts = True
            
        for contact in user['contacts']:
            if contact['type'] == 'email' and contact['value'].split('@')[0] == alias:
                results_table.add_row(
                    "Email Contact",
                    user['nickname'],
                    user['id'],
                    user.get('displayName', '')
                )
                found_conflicts = True

    scim_users = get_all_scim_users(settings)
    if scim_users:
        for user in scim_users:
            if alias == user['userName'] or alias == user['userName'].split('@')[0]:
                results_table.add_row(
                    "SCIM userName",
                    user['userName'],
                    user['id'],
                    user['displayName']
                )
                found_conflicts = True
    
    if found_conflicts:
        console.print(f"[bold red]⚠️  Alias '{alias}' is already in use:[/bold red]")
        console.print(results_table)
        console.input("[dim]Press Enter to continue...[/dim]")
    else:
        console.print(f"[bold blue]✅ Alias '{alias}' is not found in Y360![/bold blue]")

def change_nickname(settings: "SettingParams", old_value: str, new_value: str):
    logger.info(f"Changing nickname of user {old_value} to {new_value}")
    users = get_all_api360_users(settings, True)
    
    if not users:
        console.print("[bold red]❌ No users found.[/bold red]")
        return
    logger.info(f"{len(users)} users found.")

    new_value = new_value.lower()
    old_value = old_value.lower()

    target_user = [user for user in users if user['nickname'].lower() == old_value]
    if not target_user:
        logger.error(f"User with nickname {old_value} not found.")
        return
    logger.info(f"User with nickname {old_value} found. User ID - {target_user[0]['id']}")

    existing_user = [user for user in users if user['nickname'].lower() == new_value]
    if existing_user:
        logger.error(f"User with nickname {new_value} already exists. User ID - {existing_user[0]['id']}. Clear this nickname and try again.")
        return
    
    for user in users:
        if new_value in [r.lower() for r in user['aliases']] and user['nickname'].lower() != old_value:
            logger.error(f"Nickname {new_value} already exists as alias in user with nickname {user['nickname']}. User ID - {user['id']}. Clear this alias in this user and try again.")
            return
        if user['nickname'].lower() != old_value:
            for contact in user['contacts']:
                if contact['type'] == 'email' and contact['value'].split('@')[0].lower() == new_value:
                    logger.error(f"Nickname {new_value} already exists as email contact in user with nickname {user['nickname']}. User ID - {user['id']}. Clear this contact email in this user and try again.")
                    return
        else:
            for contact in user['contacts']:
                if contact['type'] == 'email' and contact['value'].split('@')[0].lower() == new_value:
                    if settings.skip_scim_api_call:
                        logger.info(f"Nickname {new_value} already found as alias in target user. Need to delete alias {new_value} in target user (uid - {user['id']}).")
                        if settings.skip_scim_api_call:
                            logger.info("SCIM API is disablled. Trying to delete alias using 360 API.")
                            remove_alias_by_api360(settings, user['id'], new_value)    
    
    if not settings.skip_scim_api_call:
        if new_value in [r.lower() for r in target_user[0]['aliases']]:
            remove_alias_in_scim(target_user[0]["id"], new_value)

        for contact in target_user[0]['contacts']:
            if contact['type'] == 'email' and contact['value'].split('@')[0].lower() == new_value:
                remove_email_in_scim(target_user[0]["id"], new_value)
    

    logger.info(f"Changing nickname of user {old_value} to {new_value}")
    raw_data = {'nickname': new_value}
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{target_user[0]['id']}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.debug(f"PATCH URL: {url}")
    logger.debug(f"PATCH DATA: {raw_data}")
    try:
        response = requests.patch(url, headers=headers, data=json.dumps(raw_data))
        logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
        if response.ok:
            logger.info(f"Nickname of user {old_value} changed to {new_value}")
            time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
        else:
            logger.error(f"Error ({response.status_code}) changing nickname of user {old_value} to {new_value}: {response.text}")
            return

    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return 
    
    if not settings.skip_scim_api_call:
        remove_alias_in_scim(target_user[0]["id"], old_value)

    logger.info("Reload list of users to reflect changes in nickname.")
    settings.all_users = None
    # users = get_all_api360_users(settings, True)

def remove_alias_by_api360(settings: "SettingParams", user_id: str, alias: str):

    logger.info(f"Removing alias {alias} in _API360_ user {user_id}")
    try:
        retries = 1
        url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{user_id}/aliases/{alias}"
        headers = {"Authorization": f"OAuth {settings.oauth_token}"}
        logger.debug(f"DELETE URL: {url}")
        
        while True:
            response = requests.delete(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during DELETE request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Deleting alias {alias} for uid {user_id} failed.")
                    break
            else:
                logger.info(f"Success - Successfully deleting alias {alias} for uid {user_id}.")
                break
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

def remove_alias_in_scim(user_id: str, alias: str):
    logger.info(f"Check if exist and removing alias {alias} in _SCIM_ user {user_id}")

    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id)
    headers = {"Authorization": f"Bearer {settings.scim_token}"}
    try:
        logger.debug(f"GET url - {url}/v2/Users/{user_id}")
        response = requests.get(f"{url}/v2/Users/{user_id}", headers=headers)
        logger.debug(f"X-Request-Id: {response.headers.get("X-Request-Id","")}")
        if response.ok:
            user = response.json()
            if user['urn:ietf:params:scim:schemas:extension:yandex360:2.0:User']['aliases']:
                compiled_alias = {}
                compiled_alias["login"] = alias
                if compiled_alias in user['urn:ietf:params:scim:schemas:extension:yandex360:2.0:User']['aliases']:
                    user['urn:ietf:params:scim:schemas:extension:yandex360:2.0:User']['aliases'].remove(compiled_alias)

                    data = json.loads("""   { "Operations":    
                                                [
                                                    {
                                                    "value": _data_,
                                                    "op": "replace",
                                                    "path": "urn:ietf:params:scim:schemas:extension:yandex360:2.0:User.aliases"
                                                    }
                                                ],
                                                "schemas": [
                                                    "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                                                ]
                                            }""".replace("_data_", json.dumps(user['urn:ietf:params:scim:schemas:extension:yandex360:2.0:User']['aliases'])))
                    
                    logger.debug(f"PATCH URL: {url}/v2/Users/{user_id}")
                    logger.debug(f"PATCH DATA: {data}")
                    response = requests.patch(f"{url}/v2/Users/{user_id}", headers=headers, data=json.dumps(data))
                    logger.debug(f"X-Request-Id: {response.headers.get("X-Request-Id","")}")
                    if response.ok:
                        logger.info(f"Alias {alias} removed in user {user_id}")
                        time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
                    else:
                        logger.error(f"Error ({response.status_code}) removing alias {alias} in user {user_id}: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

def remove_email_in_scim(user_id: str, alias: str):
    logger.info(f"Check if exist and removing email with alias {alias} in _SCIM_ user {user_id} email info.")
    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id) 
    headers = {"Authorization": f"Bearer {settings.scim_token}"}
    try:
        logger.debug(f"GET url - {url}/v2/Users/{user_id}")
        response = requests.get(f"{url}/v2/Users/{user_id}", headers=headers)
        logger.debug(f"X-Request-Id: {response.headers.get("X-Request-Id","")}")
        if response.ok:
            user = response.json()
            new_emails= []
            found_alias = False
            for email in user['emails']:
                temp = {}
                if email["value"].split('@')[0] != alias:
                    temp["primary"] = email["primary"]
                    if len(email.get("type",'')) > 0:
                        temp["type"] = email["type"]
                    temp["value"] = email["value"]
                    new_emails.append(temp)
                else:
                    found_alias = True
            
            if found_alias:
                data = json.loads("""   { "Operations":    
                                            [
                                                {
                                                "value": _data_,
                                                "op": "replace",
                                                "path": "emails"
                                                }
                                            ],
                                            "schemas": [
                                                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                                            ]
                                        }""".replace("_data_", json.dumps(new_emails)))
                
                logger.debug(f"PATCH URL: {url}/v2/Users/{user_id}")
                logger.debug(f"PATCH DATA: {data}") 
                response = requests.patch(f"{url}/v2/Users/{user_id}", headers=headers, data=json.dumps(data))
                logger.debug(f"X-Request-Id: {response.headers.get("X-Request-Id","")}")
                if response.ok:
                    logger.info(f"Alias {alias} removed from email contacts in _SCIM_ user {user_id}")
                    time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
                else:
                    logger.error(f"Error ({response.status_code}) removing alias {alias} from email contacts in _SCIM_ user {user_id}: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

def create_SCIM_userName_file(settings: "SettingParams", onlyList = False):

    users = get_all_scim_users(settings)

    if users:
        if not onlyList:
            with open(settings.users_file, "w", encoding="utf-8") as f:
                f.write("uid;displayName;old_userName;new_userName\n")
                for user in users:
                    new_userName = user["userName"]
                    if "@" in user["userName"]:
                        login = user["userName"].split("@")[0]
                        domain = ".".join(user["userName"].split("@")[1].split(".")[:-1])
                        tld = user["userName"].split("@")[1].split(".")[-1]
                        new_userName = settings.new_login_default_format.replace("alias", login).replace("domain", domain).replace("tld", tld)
                    f.write(f"{user['id']};{user['displayName']};{user['userName']};{new_userName}\n")
            logger.info(f"{len(users)} users downloaded to file {settings.users_file}")
    else:
        logger.info("No users found from SCIM call. Check your settings.")
        return []
    return users

def update_users_from_SCIM_userName_file(settings: "SettingParams"):
    user_for_change = []
    all_users = []
    with open(settings.users_file, "r", encoding="utf-8") as f:
        all_users = f.readlines()

    line_number = 1
    for user in all_users[1:]:
        line_number += 1
        if user.replace("\n","").strip():
            temp = user.replace("\n","").strip()
            try:
                uid, displayName, old_userName, new_userName = temp.split(";")
                if not all(char.isdigit() for char in uid):
                    logger.info(f"Uid {uid} is not valid ({displayName}). Skipping.")   
                    continue
                if not new_userName:
                    logger.info(f"New userName for uid {uid} ({displayName}) is empty. Skipping.")   
                    continue
                if old_userName == new_userName:
                    logger.debug(f"User {old_userName} ({displayName}) has the same new name {new_userName}. Skipping.")
                    continue
                user_for_change.append(temp)
            except ValueError:
                logger.error(f"Line number {line_number} has wrong count of values (should be 4 values, separated by semicolon. Skipping")

            except Exception as e:
                logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    
    if not user_for_change:
        logger.error(f"File {settings.users_file} is empty.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    else:
        for user in user_for_change:
            logger.debug(f"Will modify - {temp}.")

        if not Confirm.ask(f"[bold yellow]Modify userName SCIM attribute for {len(user_for_change)} users?[/bold yellow]"):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
        
    headers = {
        "Authorization": f"Bearer {settings.scim_token}"
    }
    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id) 
    for user in user_for_change:
        uid, displayName, old_userName, new_userName = user.strip().split(";")
        try:
            retries = 1
            while True:
                logger.info(f"Changing user {old_userName} to {new_userName}...")
                data = json.loads("""   { "Operations":    
                                            [
                                                {
                                                "value": "alias@domain.tld",
                                                "op": "replace",
                                                "path": "userName"
                                                }
                                            ],
                                            "schemas": [
                                                "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                                            ]
                                        }""".replace("alias@domain.tld", new_userName))
                
                logger.debug(f"PATCH URL: {url}/v2/Users/{uid}")
                logger.debug(f"PATCH DATA: {data}")
                response = requests.patch(f"{url}/v2/Users/{uid}", headers=headers, json=data)
                logger.debug(f"X-Request-Id: {response.headers.get("X-Request-Id","")}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        logger.error(f"Error. Patching user {old_userName} to {new_userName} failed.")
                        break
                else:
                    logger.info(f"Success - User {old_userName} changed to {new_userName}.")
                    break
                

        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

def show_user_attributes(settings: "SettingParams"):
    console.print(Panel(
        "[bold blue]Show User Attributes[/bold blue]\n"
        "Enter target user in one of these formats:\n"
        "• [cyan]id:<UID>[/cyan] - User ID\n"
        "• [cyan]userName:<SCIM_USER_NAME>[/cyan] - SCIM username\n"
        "• [cyan]<API_360_NICKNAME>[/cyan] - API 360 nickname\n"
        "• [cyan]<API_360_ALIAS>[/cyan] - API 360 alias\n"
        "• [cyan]<lastName>[/cyan] - User's last name",
        title="[green]User Attributes Viewer[/green]",
        border_style="blue"
    ))
    
    while True:
        answer = Prompt.ask(
            "[bold yellow]Enter target user[/bold yellow]",
            default=""
        )
        if not answer.strip():
            break
        if ":" in answer:
            key, value = answer.split(":")
            key = key.strip()
            value = value.strip().lower()
            if key.lower() not in ["id", "username"]:
                logger.error(f"Invalid key {key}. Please enter id:<UID> or userName:<SCIM_USER_NAME>.")
                break
        else:
            key = "nickname"
            value = answer.lower()

        if key == "id":
            if not all(char.isdigit() for char in value):
                logger.error(f"Invalid UID {value} (Must be numeric value). Please enter valid UID.")
                break
            if not value.startswith("113"):
                logger.error(f"Invalid UID {value} (Must be starts with 113). Please enter valid UID.")
                break

        logger.info(f"Saving user data for key {key} and value {value}.")
        users = get_all_api360_users(settings)
        scim_users = get_all_scim_users(settings)  
        if not users:
            logger.error("No users found from API 360 calls. Check your settings.")
            console.input("[dim]Press Enter to continue...[/dim]")
            break
        if not scim_users:
            if not settings.skip_scim_api_call:
                logger.error("No users found from SCIM calls. Check your settings.")
                break
        target_user = None
        target_scim_user = None
        if key in ["id", "nickname"]:
            for user in users:
                if key == "id":
                    if user["id"] == value:
                        target_user = user
                        break
                elif key == "nickname":
                    if user["nickname"].lower() == value or value in [r.lower() for r in  user["aliases"]]:
                        target_user = user
                        break
        elif key.lower() == "username":
            for user in scim_users:
                if user["userName"].lower() == value:
                    target_scim_user = user
                    break
        
        if target_user:
            if not settings.skip_scim_api_call:
                target_scim_user = [user for user in scim_users if user["id"] == target_user["id"]][0]
        elif target_scim_user:
            target_user = [user for user in users if user["id"] == target_scim_user["id"]][0]
        else:
            logger.error(f"No user found for key {key} and value {value}.")
            break
        
        # Create API 360 attributes table
        api_table = Table(title=f"API 360 attributes for user with id: {target_user['id']}")
        api_table.add_column("Attribute", style="cyan")
        api_table.add_column("Value", style="green")
        
        for k, v in target_user.items():
            if k.lower() == "contacts":
                contacts_str = ""
                for contact in v:
                    contacts_str += f"Type: {contact.get('type', '')}, Value: {contact.get('value', '')}\n"
                api_table.add_row("Contacts", contacts_str.strip())
            elif k.lower() == "aliases":
                if not v:
                    api_table.add_row("Aliases", "[]")
                else:
                    aliases_str = "\n".join(v)
                    api_table.add_row("Aliases", aliases_str)
            elif k.lower() == "name":
                name_str = ""
                for k1, v1 in v.items():
                    name_str += f"{k1}: {v1}\n"
                api_table.add_row("Name", name_str.strip())
            else:
                api_table.add_row(k, str(v))
        
        console.print(api_table)
        if not settings.skip_scim_api_call:
            # Create SCIM attributes table
            scim_table = Table(title=f"SCIM attributes for user with id: {target_scim_user['id']}")
            scim_table.add_column("Attribute", style="cyan")
            scim_table.add_column("Value", style="green")
            
            for k, v in target_scim_user.items():
                if k.lower() == "emails":
                    emails_str = ""
                    for email in v:
                        for k1, v1 in email.items():
                            emails_str += f"{k1}: {v1}\n"
                        emails_str += "---\n"
                    scim_table.add_row("Emails", emails_str.strip())
                elif k.lower() in ["metadata", "name", "meta"]:
                    meta_str = ""
                    for k1, v1 in v.items():
                        meta_str += f"{k1}: {v1}\n"
                    scim_table.add_row(k, meta_str.strip())
                elif k.lower() == "phonenumbers":
                    phones_str = ""
                    for phone in v:
                        for k1, v1 in phone.items():
                            phones_str += f"{k1}: {v1}\n"
                        phones_str += "---\n"
                    scim_table.add_row("phoneNumbers", phones_str.strip())
                elif k == "urn:ietf:params:scim:schemas:extension:yandex360:2.0:User":
                    if not v["aliases"]:
                        scim_table.add_row("aliases", "[]")
                    else:
                        aliases_str = ""
                        for alias in v["aliases"]:
                            for k1, v1 in alias.items():
                                aliases_str += f"{k1}: {v1}\n"
                        scim_table.add_row("aliases", aliases_str.strip())
                else:
                    scim_table.add_row(k, str(v))
            
            console.print(scim_table)

        with open(f"{target_user['nickname']}.txt", "w", encoding="utf-8") as f:
            f.write(f'API 360 attributes for user with id: {target_user["id"]}\n')
            f.write("--------------------------------------------------------\n")
            for k, v in target_user.items():
                if k.lower() == "contacts":
                    f.write("Contacts:\n")
                    for l in v: 
                        for k1, v1 in l.items():  
                            f.write(f" - {k1}: {v1}\n")
                        f.write(" -\n")
                elif k.lower() == "aliases":
                    if not v:
                        f.write("Aliases: []\n")
                    else:
                        f.write("Aliases:\n")
                        for l in v:
                            f.write(f" - {l}\n")
                elif k.lower() == "name":
                    f.write("Name:\n")
                    for k1, v1 in v.items():  
                        f.write(f" - {k1}: {v1}\n")
                else:
                    f.write(f"{k}: {v}\n")
            f.write("--------------------------------------------------------\n")
            if not settings.skip_scim_api_call:
                f.write("--------------------------------------------------------\n")
                f.write(f'SCIM attributes for user with id: {target_scim_user["id"]}\n')
                f.write("--------------------------------------------------------\n")
                for k, v in target_scim_user.items():
                    if k.lower() == "emails":
                        f.write("Emails:\n")
                        for l in v:
                            for k1, v1 in l.items():   
                                f.write(f" - {k1}: {v1}\n")
                            f.write(" -\n")
                    elif k.lower() == "metadata":
                        f.write("Metadata:\n")
                        for k1, v1 in v.items():  
                            f.write(f" - {k1}: {v1}\n")
                    elif k.lower() == "name":
                        f.write("name:\n")
                        for k1, v1 in v.items():  
                            f.write(f" - {k1}: {v1}\n")
                    elif k.lower() == "meta":
                        f.write("meta:\n")
                        for k1, v1 in v.items():  
                            f.write(f" - {k1}: {v1}\n")
                    elif k.lower() == "phonenumbers":
                        f.write("phoneNumbers:\n")
                        for l in v:
                            for k1, v1 in l.items():  
                                f.write(f" - {k1}: {v1}\n")
                            f.write(" -\n")
                    elif k == "urn:ietf:params:scim:schemas:extension:yandex360:2.0:User":
                        if not v["aliases"]: 
                            f.write("aliases: []\n")
                        else:
                            f.write("aliases:\n")
                            for l in v["aliases"]:
                                for k1, v1 in l.items():
                                    f.write(f" - {k1}: {v1}\n")
                    else:
                        f.write(f"{k}: {v}\n")
                f.write("--------------------------------------------------------\n")
        console.print(f"[green]✅ User attributes saved to file: {target_user['nickname']}.txt[/green]")
        logger.info(f"User attributes saved to file: {target_user['nickname']}.txt")
    return

def get_target_group_data_prompt(settings: "SettingParams", answer: str):
    result = {}, []
    
    search_type = "alias"
    if "@" in answer.strip():
        answer = answer.strip().split("@")[0]

    if all(char.isdigit() for char in answer.strip()):
        if len(answer.strip()) == 16 and answer.strip().startswith("113"):
            search_type = "uid"
        else:
            search_type = "id"
    
    search_string = answer.strip()
    logger.info(f"Searching for group for: {search_string}")
    
    groups = get_all_groups(settings)
    if not groups:
        logger.error("No groups found from API 360 calls. Check your settings.")
        return result
    
    logger.info(f"{len(groups)} groups found.")
    group_found = find_group_by_param(groups, search_string, search_type)
    
    if not group_found:
        logger.error(f"No group found with search string '{search_string}'.")
        return result

    if len(group_found) > 1:
        logger.info(f"Found multiple groups with search string '{search_string}'.")
        for group in group_found:
            logger.info(f" - {group['name']} (ID: {group['id']}, Email: {group['email']}, UID: {group['emailId']})")
        logger.info("Specify more precise search criteria to find only one group'.")
        return result
    
    target_group = group_found[0]
    settings.target_group = target_group
    logger.info(f"Group found: {target_group['name']} (ID: {target_group['id']}, Email: {target_group['email']}, UID: {target_group['emailId']})")
    return target_group, groups
        
def save_group_data_prompt(settings: "SettingParams"):
    users = []
    user_id_to_nickname = {}

    console.print(Panel(
        "[bold blue]Group Data Viewer[/bold blue]\n"
        "Enter group identifier in one of these formats:\n"
        "• [cyan]alias[/cyan] - Group alias\n"
        "• [cyan]id[/cyan] - Group ID\n"
        "• [cyan]uid[/cyan] - Group UID",
        title="[green]Group Information[/green]",
        border_style="blue"
    ))

    while True:
        answer = Prompt.ask(
            "[bold yellow]Enter group alias, id or uid[/bold yellow]",
            default=""
        )
        if not answer.strip():
            break
        
        target_group, groups = get_target_group_data_prompt(settings, answer)
        if not target_group:
            continue
        
        # Create mapping for group IDs to group names
        group_id_to_name = {}
        for group in groups:
            group_id_to_name[str(group['id'])] = group.get('name', 'Unknown')

        if not users:
            users = get_all_api360_users(settings)
            if users:
                for user in users:
                    user_id_to_nickname[user['id']] = user.get('nickname', 'Unknown')
        
        # Display group attributes in console using Rich table
        group_table = Table(title=f"Group attributes for group with id: {target_group['id']}")
        group_table.add_column("Attribute", style="cyan")
        group_table.add_column("Value", style="green")
        
        for k, v in target_group.items():
            if k.lower() == "aliases":
                if v:
                    aliases_str = "\n".join(v)
                    group_table.add_row("Aliases", aliases_str)
                else:
                    group_table.add_row("Aliases", "[]")
            elif k.lower() == "members":
                members_str = ""
                for member in v:
                    member_id = member.get('id', '')
                    member_type = member.get('type', '')
                    if member_type == 'group':
                        group_name = group_id_to_name.get(str(member_id), 'Unknown')
                        members_str += f"Type: {member_type}, ID: {member_id} ({group_name})\n"
                    else:
                        nickname = user_id_to_nickname.get(member_id, 'Unknown')
                        members_str += f"Type: {member_type}, ID: {member_id} ({nickname})\n"
                group_table.add_row("Members", members_str.strip() if members_str else "No members")
            elif k.lower() == "memberof":
                memberof_str = ""
                for member_of in v:
                    group_name = group_id_to_name.get(str(member_of), 'Unknown')
                    memberof_str += f"{member_of} ({group_name})\n"
                group_table.add_row("Member of", memberof_str.strip() if memberof_str else "Not a member of any group")
            else:
                group_table.add_row(k, str(v))
        
        console.print(group_table)
        
        # Save to file
        filename = f"group_{target_group['id']}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f'Group attributes for group with id: {target_group["id"]}\n')
            f.write("--------------------------------------------------------\n")
            
            for k, v in target_group.items():
                if k.lower() == "aliases":
                    f.write("Aliases:\n")
                    for alias_item in v:
                        f.write(f" - {alias_item}\n")
                elif k.lower() == "members":
                    f.write("Members:\n")
                    for member in v:
                        member_id = member.get('id', '')
                        member_type = member.get('type', '')
                        if member_type == 'group':
                            group_name = group_id_to_name.get(str(member_id), 'Unknown')
                            f.write(f" - type: {member_type}, id: {member_id} ({group_name})\n")
                        else:
                            nickname = user_id_to_nickname.get(member_id, 'Unknown')
                            f.write(f" - type: {member_type}, id: {member_id} ({nickname})\n")
                elif k.lower() == "memberof":
                    f.write("Member of:\n")
                    for member_of in v:
                        # member_of should be a group ID, find the group name
                        group_name = group_id_to_name.get(str(member_of), 'Unknown')
                        f.write(f" - {member_of} ({group_name})\n")
                else:
                    f.write(f"{k}: {v}\n")
            
            f.write("--------------------------------------------------------\n")
        
        console.print(f"[green]✅ Group attributes saved to file: {filename}[/green]")
    return

def show_mailing_list_permissions(settings: "SettingParams", input_group = {}):
    users = []
    user_id_to_nickname = {}
    user_id_to_name = {}
    if not input_group:
        console.print(Panel(
            "[bold blue]Mailing List Permissions Viewer[/bold blue]\n"
            "Enter group identifier to view send permissions",
            title="[green]Group Permissions[/green]",
            border_style="blue"
        ))
    
    while True:
        if not input_group:
            answer = Prompt.ask(
                "[bold yellow]Enter group alias, id or uid to get mailing list permissions[/bold yellow]",
                default=""
            )
            if not answer.strip():
                break
        else:
            answer = str(input_group["id"])
            
        target_group, groups = get_target_group_data_prompt(settings, answer)
        if not target_group:
            continue
     
        if not users:
            users = get_all_api360_users(settings)

        if not user_id_to_nickname:
            for user in users:
                user_id_to_nickname[user['id']] = user.get('nickname', 'Unknown')
                name = user.get('name', {})
                user_id_to_name[user['id']] = f"{name.get('last', '')} {name.get('first', '')} {name.get('middle', '')}" 
        
        # Get mailing list permissions
        permissions = get_mailing_list_permissions(settings, target_group['emailId'])
        if permissions is None:
            logger.error(f"Failed to get mailing list permissions for group {target_group['name']}")
            continue

        shared_mailboxes = []
        need_load_shared_mailboxes = False
        if 'grants' in permissions and 'items' in permissions['grants']:
            for item in permissions['grants']['items']:
                if 'subject' in item:
                    subject = item['subject']
                    subject_type = subject.get('type', 'unknown')
                    if subject_type == 'shared_mailbox':
                        need_load_shared_mailboxes = True
                        break
        if need_load_shared_mailboxes:
            shared_mailboxes = get_all_shared_mailboxes(settings)   

        shared_mailboxes_dict = {}
        for shared_mailbox in shared_mailboxes:
            shared_mailboxes_dict[shared_mailbox['id']] = shared_mailbox           
        
        # Display results using Rich components
        group_name = target_group.get('name', 'Unknown')
        group_id = target_group['id']
        group_email = target_group.get('email', 'Unknown')
        
        # Create group info table
        group_info_table = Table(show_header=False, box=box.SIMPLE)
        group_info_table.add_column("Attribute", style="cyan")
        group_info_table.add_column("Value", style="green")
        group_info_table.add_row("Name:", group_name)
        group_info_table.add_row("ID:", str(group_id))
        group_info_table.add_row("Email:", group_email)
        group_info_table.add_row("EmailId:", str(target_group.get('emailId', 'Unknown')))
        
        group_panel = Panel(
            group_info_table,
            title="[bold blue]Group Information[/bold blue]",
            border_style="blue"
        )
        console.print(group_panel)
        
        # Create approved senders table
        senders_table = Table(title="Approved Senders")
        senders_table.add_column("Type", style="cyan")
        senders_table.add_column("ID", style="yellow")
        senders_table.add_column("Details", style="green")
        
        count_senders = 0
        if 'grants' in permissions and 'items' in permissions['grants']:
            for item in permissions['grants']['items']:
                if 'subject' in item:
                    count_senders += 1
                    subject = item['subject']
                    subject_type = subject.get('type', 'unknown')
                    subject_id = subject.get('id', 'null')
                    
                    if subject_type == 'user':
                        subject_org = subject.get('org_id', 'unknown')
                        if str(subject_org) == str(settings.org_id):
                            nickname = user_id_to_nickname.get(str(subject_id), 'Unknown')
                            name = user_id_to_name.get(str(subject_id), '')
                            senders_table.add_row(subject_type, str(subject_id), f"Nickname: {nickname}, Name: {name}")
                    elif subject_type == 'anonymous':
                        senders_table.add_row(subject_type, "N/A", "Anyone can send")
                    elif subject_type == 'organization':
                        senders_table.add_row(subject_type, str(subject.get('org_id', '')), "Organization members")
                    elif subject_type == 'shared_mailbox':
                        name = shared_mailboxes_dict.get(str(subject_id), {}).get('name', 'Unknown')
                        email = shared_mailboxes_dict.get(str(subject_id), {}).get('email', 'Unknown')
                        senders_table.add_row(subject_type, str(subject_id), f"Name: {name}, Email: {email}")
                    else:
                        senders_table.add_row(subject_type, str(subject.get('id', '')), f"Org: {subject.get('org_id', '')}")
        
        if count_senders == 0:
            console.print("[bold red]⚠️  WARNING: NOBODY can send mail to this group![/bold red]")
            senders_table.add_row("None", "N/A", "No permission subjects found")
        
        console.print(senders_table)
        
        # if not input_group:
        #     console.input("[dim]Press Enter to continue...[/dim]")

        if input_group:
            break
    return

def get_mailing_list_permissions(settings: "SettingParams", group_id: str):
    """Get mailing list permissions for a group using cloud-api.yandex.net API"""
    logger.debug(f"Getting mailing list permissions for group {group_id}...")
    
    # The API endpoint from the documentation
    url = f"https://cloud-api.yandex.net/v1/admin/org/{settings.org_id}/mail-lists/{group_id}/permissions"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    
    try:
        retries = 1
        while True:
            logger.debug(f"GET url - {url}")
            response = requests.get(url, headers=headers)
            logger.debug(f"Yandex-Cloud-Request-ID: {response.headers["Yandex-Cloud-Request-ID"]}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request for group {group_id}: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Getting mailing list permissions for group {group_id} failed.")
                    return None
            else:
                data = response.json()
                logger.debug(f"Successfully retrieved mailing list permissions for group {group_id}")
                logger.debug(f"url - GET {url}")
                logger.debug(f"Raw JSON -  {data}")
                return data
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return None

def download_users_attrib_to_file(settings: "SettingParams"):
    users = get_all_api360_users(settings, force=True)
    scim_users = get_all_scim_users(settings)  
    if not users:
        logger.error("No users found from API 360 calls.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    else:
        with open('api_users.csv', 'w', encoding='utf-8', newline='') as csv_file:
            fieldnames = list(users[0].keys())
            if "isEnabledUpdatedAt" not in fieldnames:
                fieldnames.append("isEnabledUpdatedAt")
            writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
            writer.writeheader()
            for user in users:
                writer.writerow(user)
            logger.info(f"Saved {len(users)} API users to api_users.csv")
    if not scim_users:
        logger.error("No users found from SCIM calls.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    else:
        with open('scim_users.csv', 'w', encoding='utf-8', newline='') as csv_file:
            fieldnames = scim_users[0].keys()
            writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
            writer.writeheader()
            for user in scim_users:
                writer.writerow(user)
            logger.info(f"Saved {len(scim_users)} SCIM users to scim_users.csv")

    console.input("[dim]Press Enter to continue...[/dim]")

def default_email_create_file(settings: "SettingParams"):
    users = get_all_api360_users(settings)
    if not users:
        logger.error("No users found from API 360 calls.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    else:
        email_dict = {}
        nickname_dict = {}
        with console.status(f"[bold green]Downloading default emails for {len(users)} users...", spinner="dots"):
        #logger.info(f"Downloading default emails for {len(users)} users...")
            count = 0
            total = len(users)
            for user in users:
                if user["id"].startswith("113"):
                    default_email_json = get_default_email(settings, user["id"])
                    count += 1
                    if divmod(count, 50)[1] == 0:
                        logger.info(f"Got default email for {count} of {total} users.")
                    email_dict[user["id"]] = default_email_json
                    nickname_dict[user["id"]] = user["nickname"]

        with open(settings.default_email_output_file, "w", encoding="utf-8") as f:
            f.write("nickname;new_DefaultEmail;new_DisplayName;old_DefaultEmail;old_DisplayName;uid\n")
            for key in email_dict.keys():
                email_data = email_dict[key]
                if email_data:
                    f.write(f"{nickname_dict[key]};{email_data['defaultFrom']};{email_data['fromName']};{email_data['defaultFrom']};{email_data['fromName']};{key}\n")
            logger.info(f"Default emails downloaded to {settings.default_email_output_file} file.")
            console.input("[dim]Press Enter to continue...[/dim]")

def default_email_update_from_file(settings: "SettingParams"):
    all_users = []
    exit_flag = False
    only_email = False

    try:
        with open(settings.default_email_input_file, "r", encoding="utf-8") as f:
            all_users = f.readlines()
    except FileNotFoundError:
        logger.error(f"Input file {settings.default_email_input_file} not found. Exiting.")
        exit_flag = True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        exit_flag = True

    if all_users == []:
        logger.error(f"Input file {settings.default_email_input_file} is empty. Exiting.")
        exit_flag = True

    if exit_flag:
        console.input("[dim]Press Enter to continue...[/dim]")
        return

    if "@" in all_users[0] and ";" not in all_users[0]:
        logger.info("Input file contains single column. Use it as target default email for all users.")
        only_email = True
    else:
        all_users = [] 
        try:
            with open(settings.default_email_input_file, mode='r', newline='', encoding='utf-8') as file:
                reader = csv.DictReader(file, delimiter=';')
                headers = reader.fieldnames
                for row in reader:
                    all_users.append(row) 

        except FileNotFoundError:
            logger.error(f"Input file {settings.default_email_input_file} not found. Exiting.")
            exit_flag = True
        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
            exit_flag = True
        
    if exit_flag:
        console.input("[dim]Press Enter to continue...[/dim]")
        return

    exit_flag = False
    
    normalized_users = []
    for user in all_users:
        if only_email:
            if "@" in user:
                user = user.strip("\n").strip().lower()
                normalized_users.append({"nickname": user.split("@")[0], "new_DefaultEmail": user, "new_DisplayName": "", "old_DefaultEmail": "", "old_DisplayName": "", "uid": ""})
                continue
        else:
            if "nickname" not in user:
                exit_flag = True
                break
            else:
                if user["nickname"] is None or user["nickname"].strip() == "":
                    continue
                else:
                    user["nickname"] = user["nickname"].strip().lower()

            email_empty = False
            if "new_DefaultEmail" not in user:  
                user["new_DefaultEmail"] = ""
                email_empty = True
            else:
                if user["new_DefaultEmail"] is None or user["new_DefaultEmail"].strip() == "":
                    user["new_DefaultEmail"] = ""
                    email_empty = True
                else:
                    if "@" not in user["new_DefaultEmail"].strip():
                        continue
                    else:
                        user["new_DefaultEmail"] = user["new_DefaultEmail"].strip().lower()
                        

            name_empty = False
            if "new_DisplayName" not in user:  
                user["new_DisplayName"] = ""
                name_empty = True
            else:
                if user["new_DisplayName"] is None or user["new_DisplayName"].strip() == "":
                    user["new_DisplayName"] = ""
                    name_empty = True

            if email_empty and name_empty:
                continue

            if "old_DefaultEmail" not in user:  
                user["old_DefaultEmail"] = ""
            if "old_DisplayName" not in user:  
                user["old_DisplayName"] = "" 
            if "uid" not in user:  
                user["uid"] = ""   
            normalized_users.append(user)

    if exit_flag:
        logger.error("There are must be column 'nickname' in input file ('default_email_data.csv').")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    if not normalized_users:
        logger.info("List of modified users is empty. File must contains column 'nickname' and actual data in 'new_DefaultEmail' or 'new_DisplayName' columns.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    if not Confirm.ask(f"[bold yellow]Modify personal email data for {len(normalized_users)} users?[/bold yellow]"):
        console.print("[yellow]Operation cancelled.[/yellow]")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    api_users = get_all_api360_users(settings)
    if not api_users:
        logger.error("No users found from API 360 calls.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mail/users" 
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    for user in normalized_users:
        if "@" in user["nickname"]:
            alias = user["nickname"].strip().split("@")[0]
        else:
            alias = user["nickname"].strip()
        uid = ""
        for api_user in api_users:
            if api_user["nickname"] == alias:
                if api_user["id"].startswith("113"):
                    uid = api_user["id"]
                    break
            else:
                if alias in api_user["aliases"]:
                    if api_user["id"].startswith("113"):
                        uid = api_user["id"]
                        break

        if not uid:
            logger.error(f"User with nickname {alias} not found in API 360 calls.")
            continue

        try:
            retries = 1
            data = get_default_email(settings, uid)
            if not data:
                logger.error(f"Can not get email config for user {uid} with alias {alias}.")
                continue
            change_name = False
            change_mail = False
            if user["new_DisplayName"].strip(): 
                if data["fromName"] != user["new_DisplayName"].strip():
                    change_name = True
            if user["new_DefaultEmail"].strip(): 
                if data["defaultFrom"].lower() != user["new_DefaultEmail"].strip().lower():
                    change_mail = True 
            if not (change_name or change_mail):
                logger.info(f"Skipping to change email configuration for user {uid} with alias {alias} - nothing to change...")
                continue   
            else:
                logger.info(f"Changing user {uid} with alias {alias}: {data["fromName"]} ({data["defaultFrom"]}) to {user["new_DisplayName"]} ({user["new_DefaultEmail"]})...")
            while True:
                if change_name:
                    data["fromName"] = user["new_DisplayName"].strip()
                if change_mail:
                    data["defaultFrom"] = user["new_DefaultEmail"].strip()
                logger.debug(f"POST URL: {url}/{uid}/settings/sender_info")
                logger.debug(f"POST DATA: {data}")
                response = requests.post(f"{url}/{uid}/settings/sender_info", headers=headers, json=data)
                logger.debug(f"x-request-id: {response.headers.get("X-Request-Id","")}")
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"Error during POST request: {response.status_code}. Error message: {response.text}")
                    if retries < MAX_RETRIES:
                        logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                        time.sleep(RETRIES_DELAY_SEC * retries)
                        retries += 1
                    else:
                        logger.error(f"Error. Patching email data for user {uid} ({alias}) failed.")
                        break
                else:
                    logger.info(f"Success - email data for user {uid} ({alias}) changed successfully.")
                    break
        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    console.input("[dim]Press Enter to continue...[/dim]")

def send_perm_set_target_group(settings: "SettingParams"):
    console.print(Panel(
        "[bold blue]Set Target Group[/bold blue]\n"
        "Select a group to manage send permissions for",
        title="[green]Target Group Selection[/green]",
        border_style="blue"
    ))
    
    while True:
        answer = Prompt.ask(
            "[bold yellow]Enter group alias, id or uid[/bold yellow]",
            default=""
        )
        if not answer.strip():
            break
        
        target_group, groups = get_target_group_data_prompt(settings, answer)
        
        if not target_group:
            continue
        elif str(target_group["emailId"]) == "0":
            console.print(f"[bold red]❌ Group with alias {answer} is not mail enabled.[/bold red]")
            settings.target_group = {}
            console.input("[dim]Press Enter to continue...[/dim]")
            continue
        else:
            console.print(f"[bold green]✅ Target group set: {target_group['name']} ({target_group['id']}, {target_group['emailId']})[/bold green]")
            console.input("[dim]Press Enter to continue...[/dim]")
            break
    return

def send_perm_add_users_to_allow_list_prompt(settings: "SettingParams"):

    if not settings.target_group:
        logger.error("No target group set. Exiting.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    while True:

        break_flag, double_users_flag, users_to_add = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue
        
        if not users_to_add:
            logger.info("No users to add. Exiting.")
            continue

        if send_perm_call_api(settings, users_to_add, "ADD_USER", []):
            show_mailing_list_permissions(settings, settings.target_group)
            console.input("[dim]Press Enter to continue...[/dim]")
            break

        

def send_perm_remove_users_from_allow_list(settings: "SettingParams"):

    if not settings.target_group:
        logger.error("No target group set. Exiting.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    while True:
        break_flag, double_users_flag, users_to_remove = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue
        
        if not users_to_remove:
            logger.info("No users to remove. Exiting.")
            continue

        if send_perm_call_api(settings, users_to_remove, "REMOVE_USER", []):
            show_mailing_list_permissions(settings, settings.target_group)
            console.input("[dim]Press Enter to continue...[/dim]")
            break
        
def send_perm_grand_all_users(settings: "SettingParams"):

    if not settings.target_group:
        logger.error("No target group set. Exiting.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    show_mailing_list_permissions(settings, settings.target_group)

    if Confirm.ask("[bold yellow]⚠️  Need confirmation for setting grand all permission?[/bold yellow]"):
        if send_perm_call_api(settings, None, "SET_DEFAULT", []):
            show_mailing_list_permissions(settings, settings.target_group)
            console.input("[dim]Press Enter to continue...[/dim]")
    else:
        console.print("[red]❌ Execution canceled.[/red]")

    return

def get_shared_mailbox_detail(settings: "SettingParams"):
     
    shared_mailboxes = []    
    result, shared_from_api = get_shared_mailboxes_from_api(settings)
    if not result:
        logger.error("Can not get shared mailboxes from API.")
        return False, []
    if not shared_from_api:
        logger.info("List of shared mailboxes, received from API is empty. Exiting.")
        return True, []
    count = 0
    logger.info(f"Get detail information for {len(shared_from_api)} shared mailboxex.")
    for api_shared_mailbox in shared_from_api:
        temp = get_shared_mailbox_details_from_api(settings, api_shared_mailbox["resourceId"])
        count += 1
        if divmod(count, 10)[1] == 0:
            logger.info(f"Got info for {count} shared mailboxes. Total count - {len(shared_from_api)}")
        if temp:
            shared_mailboxes.append(temp)
    if not shared_mailboxes:
        logger.error("Can not get shared mailboxes details from API. Exiting.")
        return False, []
    
    return True, shared_mailboxes

def send_perm_shared_mailbox(settings: "SettingParams"):

    if not settings.target_group:
        logger.error("No target group set. Exiting.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    shared_mailboxes = get_all_shared_mailboxes(settings)
    if not shared_mailboxes:
        logger.info("List of shared mailboxes is empty.")
        return
    
    while True:

        show_mailing_list_permissions(settings, settings.target_group)
        console.print(Panel(
        "[bold blue]Add shared mailbox to group send permissions[/bold blue]\n"
        "Enter target shared mailboxes emails, aliases or part of name in one of these formats (with + or -), separated by comma or space:\n"
        "• [cyan]<alias>[/cyan] - shared mailbox alias\n"
        "• [cyan]<email>[/cyan] - shared mailbox email\n"
        "• [cyan]<NAME>[/cyan] - part of shared mailbox name\n",
        title="[green]Shared mailbox adding[/green]",
        border_style="blue"
        ))
    
        answer = Prompt.ask(
            "[bold yellow]Enter shared mailbox[/bold yellow]",
            default=""
        )
        # logger.info("To add shared mailbox to list, type +email_of_shared_mailbox, to remove from list, type -email_of_shared_mailbox.")
        # answer = input("Enter shared mailboxes emails, aliases or part of name (with + or -), separated by comma or space (empty string to exit): ")
        if not answer.strip():
            break

        pattern = r'[;,\s]+'
        shared_mailboxes_for_search = re.split(pattern, answer)
        data_to_add = []
        for search_mailbox in shared_mailboxes_for_search:
            if search_mailbox.startswith("+"):
                op = "ADD_SHARED_MAILBOX"
                temp = search_mailbox[1:]
            elif search_mailbox.startswith("-"):
                op = "REMOVE_SHARED_MAILBOX"
                temp = search_mailbox[1:]
            else:
                op = "ADD_SHARED_MAILBOX"
                temp = search_mailbox

            found_mailbox = False
            if "@" in temp:
                for shared_mailbox in shared_mailboxes:
                    if shared_mailbox["email"] == temp:
                        found_mailbox = True
                        logger.info(f"Shared mailbox with name {temp} found:")
                        logger.info(f" - name{shared_mailbox['name']}, email {shared_mailbox['email']}, description {shared_mailbox['description']}")
                        logger.info("Adding to list of permissions.")
                        data_to_add.append({"op":op,"mailbox":shared_mailbox})
                        break
                if not found_mailbox:
                    logger.error(f"Shared mailbox {temp} not found. Skip adding to list of permissions.")
                    continue
            else:
                found_in_name_count = 0
                found_in_name_list = []
                for shared_mailbox in shared_mailboxes:
                    if temp.lower() == shared_mailbox["email"].lower().split("@")[0]:
                        found_mailbox = True
                        data_to_add.append({"op":op,"mailbox":shared_mailbox})
                        break
                if not found_mailbox:
                    for shared_mailbox in shared_mailboxes:
                        if temp.lower() in shared_mailbox["name"].lower():
                            found_in_name_count += 1
                            found_in_name_list.append(shared_mailbox)
                    if found_in_name_count > 1:
                        logger.error(f"Found more than one shared mailbox with name {temp}:")
                        for info in found_in_name_list:
                            logger.error(f" - name {info['name']}, email {info['email']}, description {info['description']}")
                        logger.error("Skip adding to list of permissions shared mailbox with name {temp}.")
                        continue
                    elif found_in_name_count == 1:
                        data_to_add.append({"op":op,"mailbox":found_in_name_list[0]})
                        logger.info(f"Shared mailbox with name {temp} found:")
                        logger.info(f" - name{found_in_name_list[0]['name']}, email {found_in_name_list[0]['email']}, description {found_in_name_list[0]['description']}")
                        logger.info("Adding to list of permissions.")
                        continue
                    else:
                        logger.error(f"Shared mailbox with name {temp} not found. Skip adding to list of permissions.")
                        continue

        if not data_to_add:
            logger.error("No shared mailboxes to change in send permissions. Exiting.")
            continue

        added_list = [v["mailbox"] for v in data_to_add if v["op"] == "ADD_SHARED_MAILBOX"]
        removed_list = [v["mailbox"] for v in data_to_add if v["op"] == "REMOVE_SHARED_MAILBOX"]

        if added_list:
            send_perm_call_api(settings, None, "ADD_SHARED_MAILBOX", added_list)

        if removed_list:
            send_perm_call_api(settings, None, "REMOVE_SHARED_MAILBOX", removed_list)

        # show_mailing_list_permissions(settings, settings.target_group)
    
    return

def send_perm_call_api(settings: "SettingParams", users_to_change, mode, shared_mailboxes):
    url = f"{DEFAULT_360_API_URL_V2}/{settings.org_id}/mail-lists/{settings.target_group['emailId']}/update-permissions"
    headers = {
        "Authorization": f"OAuth {settings.oauth_token}",
        "Content-Type": "application/json"
    }
    return_value = False    
    subjects = []
    data = {}
    data["role_actions"] = []
    #проверяем, что в группе нет разрешения на anonymous, иначе удаляем его
    permissions = get_mailing_list_permissions(settings, settings.target_group['emailId'])
    if permissions is None:
            logger.error(f"Failed to get mailing list permissions for group {settings.target_group['name']}. Exiting.")
            return return_value

    if mode.startswith("ADD"):
        if 'grants' in permissions and 'items' in permissions['grants']:
            for item in permissions['grants']['items']:
                if 'subject' in item:
                    subject = item['subject']
                    subject_type = subject.get('type', 'unknown')
                    if subject_type == 'anonymous':
                        logger.info("Found anonymous permission. Removing it...")
                        subjects.append({  
                            "type": "anonymous",
                            "id": 0
                        })
                        data["role_actions"].append({  
                            "type": "revoke",  
                            "roles": ["mail_list_sender"],  
                            "subjects": subjects
                        })

    if mode == "ADD_USER":
        subjects = []
        for user in users_to_change:
            subjects.append({  
                "type": "user",  
                "id": int(user["id"]),  
                "org_id": int(settings.org_id)  
                })

        data["role_actions"].append({  
            "type": "grant",  
            "roles": ["mail_list_sender"],  
            "subjects": subjects  
        })

    elif mode == "SET_DEFAULT":
        subjects = []
        for item in permissions['grants']['items']:
            if 'subject' in item:
                if item['subject']['type'] != 'anonymous':
                    subjects.append(item['subject'])

        if subjects:
            data["role_actions"].append({
                "type": "revoke",  
                "roles": ["mail_list_sender"],  
                "subjects": subjects
            })

        data["role_actions"].append({  
            "type": "overwrite",  
            "roles": ["mail_list_sender"],  
            "subjects": [{  
                "type": "anonymous",  
                "id": 0  
            }]  
        })

    elif mode == "REMOVE_USER":
        subjects = []
        for item in permissions['grants']['items']:
            if 'subject' in item:
                if item['subject']['type'] == 'user':
                    if str(item['subject']['id']) in [user['id'] for user in users_to_change]:
                        subjects.append(item['subject'])

        if subjects:
            data["role_actions"].append({
                "type": "revoke",  
                "roles": ["mail_list_sender"],  
                "subjects": subjects
            })

    elif mode == "ADD_SHARED_MAILBOX":

        subjects = []
        for mailbox in shared_mailboxes:
            subjects.append({  
                "type": "shared_mailbox",  
                "id": int(mailbox["id"]),  
                "org_id": int(settings.org_id)  
                })

        data["role_actions"].append({  
            "type": "grant",  
            "roles": ["mail_list_sender"],  
            "subjects": subjects  
        })

    elif mode == "REMOVE_SHARED_MAILBOX":
        subjects = []
        for item in permissions['grants']['items']:
            if 'subject' in item:
                if item['subject']['type'] == 'shared_mailbox':
                    if str(item['subject']['id']) in [mailbox['id'] for mailbox in shared_mailboxes]:
                        subjects.append(item['subject'])

        if subjects:
            data["role_actions"].append({
                "type": "revoke",  
                "roles": ["mail_list_sender"],  
                "subjects": subjects
            })

    if not data["role_actions"]:
        logger.error("No subjects to modify for send permissions for group {settings.target_group['name']}. Exiting.")
        return return_value
    elif not data["role_actions"][0]["subjects"]:
        logger.error("No subjects to modify for send permissions for group {settings.target_group['name']}. Exiting.")
        return return_value
    try:
        retries = 1
        while True:
            logger.debug(f"POST url: {url}")
            logger.debug(f"Raw POST JSON: {json.dumps(data)})")
            response = requests.post(url, headers=headers, json=data)
            logger.debug(f"Yandex-Cloud-Request-ID: {response.headers["Yandex-Cloud-Request-ID"]}")
            if not (response.status_code == 200 or response.status_code == 204):
                logger.error(f"Error during POST request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Change send permissions for group {settings.target_group['name']} ({settings.target_group['id']}, {settings.target_group['emailId']}) failed.")
                    break
            else:
                logger.info(f"Success - permissions for group {settings.target_group['name']} ({settings.target_group['id']}, {settings.target_group['emailId']}) changed successfully.")
                return_value = True
                break
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

    return return_value

def get_shared_mailboxes_from_api(settings: "SettingParams"):
    logger.info("Get shared mailboxes from API.")
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mailboxes/shared" 
    headers = {
        "Authorization": f"OAuth {settings.oauth_token}",
    }
    shared_list = []
    params = {}
    
    try:
        params["perPage"] = 100
        params["page"] = 1
        retries = 0
        while True: 
            logger.debug(f"GET url: {url}")
            logger.debug(f"GET Params: {params}")
            response = requests.get(url, headers=headers, params=params)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Forcing exit without getting data.")
                    return False, []
            else:
                retries = 1
                temp_list = response.json()["resources"]
                if temp_list:
                    logger.info(f'Got page {params['page']} of {divmod(int(response.json()["total"]), params["perPage"])[0] +1} pages ({params["perPage"]} records per page).')
                    shared_list.extend(temp_list)
                    
                    if  params["page"] < divmod(int(response.json()["total"]), params["perPage"])[0] + 1 :
                        params["page"] += 1
                    else:
                        break

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return False, []

    return True, shared_list

def get_shared_mailbox_details_from_api(settings: "SettingParams", shared_mailbox_id: str):
    logger.debug(f"Get shared mailbox details from API (id - {shared_mailbox_id}).")
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mailboxes/shared/{shared_mailbox_id}"
    headers = {
        "Authorization": f"OAuth {settings.oauth_token}",
    }
    try:
        retries = 0
        while True: 
            logger.debug(f"GET url: {url}")
            response = requests.get(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.debug(f"Error during GET request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error("Forcing exit without getting data.")
                    return
            else:
                break

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return
    
    return response.json()

def forward_rules_get_for_user(settings: "SettingParams"):
    logger.info("Get forward rules for users.")
    while True:
        
        break_flag, double_users_flag, users_to_add = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue

        if not users_to_add:
            logger.info("No users to add. Exiting.")
            continue

        for user in users_to_add:
            forward_rules_show_for_user(settings, user)
            
def forward_rules_show_for_user(settings: "SettingParams", user):
    with console.status(f"[bold green]Getting forward rules for user {user['nickname']}...", spinner="dots"):
        response_json = get_forward_rules_from_api(settings, user)

    # Create user info table
    user_table = Table(show_header=False, box=box.SIMPLE)
    user_table.add_column("Attribute", style="cyan")
    user_table.add_column("Value", style="green")
    
    full_name = f"{user['name']['last']} {user['name']['first']} {user['name']['middle']}"
    user_table.add_row("Name:", full_name)
    user_table.add_row("Nickname:", user['nickname'])
    user_table.add_row("User ID:", user['id'])
    user_table.add_row("Position:", user.get('position', 'N/A'))
    
    if 'aliases' in user and user['aliases']:
        aliases_str = ", ".join(user['aliases'])
        user_table.add_row("Aliases:", aliases_str)
    
    user_panel = Panel(
        user_table,
        title="[bold blue]User Information[/bold blue]",
        border_style="blue"
    )
    
    # Create forward rules table
    forward_table = Table(title="Forward Rules")
    forward_table.add_column("Address", style="green")
    forward_table.add_column("Save in Mailbox", style="cyan")
    forward_table.add_column("Rule Name", style="yellow")
    
    if response_json["forwards"]:
        for forward in response_json["forwards"]:
            save_status = "✅ Yes" if forward['withStore'] else "❌ No"
            forward_table.add_row(
                forward['address'],
                save_status,
                forward.get('ruleName', 'N/A')
            )
    else:
        forward_table.add_row("No forward rules found", "N/A", "N/A")
    
    # Create autoreplies table
    autoreply_table = Table(title="Autoreply Rules")
    autoreply_table.add_column("Text", style="green")
    autoreply_table.add_column("Rule ID", style="yellow")
    
    if response_json["autoreplies"]:
        for autoreply in response_json["autoreplies"]:
            autoreply_table.add_row(
                autoreply['text'][:50] + "..." if len(autoreply['text']) > 50 else autoreply['text'],
                str(autoreply.get('ruleId', 'N/A'))
            )
    else:
        autoreply_table.add_row("No autoreply rules found", "N/A")
    
    console.print(user_panel)
    console.print(forward_table)
    console.print(autoreply_table)
    console.input("[dim]Press Enter to continue...[/dim]")

def forward_rules_clear_for_user(settings: "SettingParams"):
    logger.info("Clear forward and autoreply rules for users.")
    while True:
        
        break_flag, double_users_flag, users_to_clear = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue

        if not users_to_clear:
            logger.info("No users to clear. Exiting.")
            continue

        for user in users_to_clear:
            get_and_clear_forward_rules_by_userid(settings, user)

def find_users_prompt(settings: "SettingParams"):
    break_flag = False
    double_users_flag = False

    answer = Prompt.ask(
        "[bold yellow]Enter users aliases or uid or last name, separated by comma or space[/bold yellow]",
        default=""
    )
    if not answer.strip():
        break_flag = True

    users = get_all_api360_users(settings)
    if not users:
        logger.info("No users found in Y360 organization.")
        break_flag = True

    pattern = r'[;,\s]+'
    search_users = re.split(pattern, answer)
    users_to_add = []
    #rus_pattern = re.compile('[-А-Яа-яЁё]+')
    #anti_rus_pattern = r'[^\u0400-\u04FF\s]'

    for searched in search_users:
        if "@" in searched.strip():
            searched = searched.split("@")[0]
        found_flag = False
        if all(char.isdigit() for char in searched.strip()):
            if len(searched.strip()) == 16 and searched.strip().startswith("113"):
                for user in users:
                    if user["id"] == searched.strip():
                        logger.debug(f"User found: {user['nickname']} ({user['id']})")
                        users_to_add.append(user)
                        found_flag = True
                        break

        else:
            found_last_name_user = []
            for user in users:
                aliases_lower_case = [r.lower() for r in user["aliases"]]
                if user["nickname"].lower() == searched.lower().strip() or searched.lower().strip() in aliases_lower_case:
                    logger.debug(f"User found: {user['nickname']} ({user['id']})")
                    users_to_add.append(user)
                    found_flag = True
                    break
                if user["name"]["last"].lower() == searched.lower().strip():
                    found_last_name_user.append(user)
            if not found_flag and found_last_name_user:
                if len(found_last_name_user) == 1:
                    logger.debug(f"User found ({searched}): {found_last_name_user[0]['nickname']} ({found_last_name_user[0]['id']}, {found_last_name_user[0]['position']})")
                    users_to_add.append(found_last_name_user[0])
                    found_flag = True
                else:
                    logger.error(f"User {searched} found more than one user:")
                    for user in found_last_name_user:
                        logger.error(f" - last name {user['name']['last']}, nickname {user['nickname']} ({user['id']}, {user['position']})")
                    logger.error("Refine your search parameters.")
                    double_users_flag = True
                    break

        if not found_flag:
            logger.error(f"User {searched} not found in Y360 organization.")

    return break_flag, double_users_flag, users_to_add

def get_forward_rules_from_api(settings: "SettingParams", user):
    logger.debug(f"Getting forward rule for user {user["id"]} ({user["nickname"]})...")
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mail/users/{user["id"]}/settings/user_rules"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    data = {}
    try:
        retries = 1
        while True:
            logger.debug(f"GET url - {url}")
            response = requests.get(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request for user {user["id"]}: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Getting forward rules for user {user["id"]} ({user["nickname"]}) failed.")
                    break
            else:
                data = response.json()
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    return data

def get_and_clear_forward_rules_by_userid(settings: "SettingParams", user):
    #logger.info(f"Getting forward rules for user {user["id"]} ({user["nickname"]})...")
    rules = get_forward_rules_from_api(settings, user)
    if not rules:
        logger.info(f"No forward or autoreplays rules found for user {user["id"]} ({user["nickname"]}).")
        return
    rules_ids = []
    if rules["forwards"]:
        for forward in rules["forwards"]:
            logger.info(f"Clearing forwards rule {forward["ruleId"]}: address - {forward["address"]}, save and forward - {forward['withStore']}, rule name - {forward['ruleName']}.")
            rules_ids.append(forward["ruleId"])
    else:
        logger.info(f"No forward rules found for user {user["id"]} ({user["nickname"]}).")
    if rules["autoreplies"]:
        for autoreply in rules["autoreplies"]:
            logger.info(f"Clearing autoreply rule {autoreply["ruleId"]}: text - {autoreply["text"]}.")
            rules_ids.append(autoreply["ruleId"])
    else:
        logger.info(f"No autoreply rules found for user {user["id"]} ({user["nickname"]}).")
    if rules_ids:
        for rule_id in rules_ids:
            clear_forward_rule_by_api(settings, user, rule_id)
        forward_rules_show_for_user(settings, user)

def clear_forward_rule_by_api(settings: "SettingParams", user, ruleId):

    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mail/users/{user["id"]}/settings/user_rules/{ruleId}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    logger.info(f"Clearing forward rule {ruleId} for user {user["id"]} ({user["nickname"]})...")
    logger.debug(f"DELETE URL: {url}")
    try:
        retries = 1
        while True:
            
            response = requests.delete(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during DELETE request for user {user["id"]}: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Clearing forward rules for user {user["id"]} ({user["nickname"]}) failed.")
                    break
            else:
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return

def forward_rules_download_for_all_users(settings: "SettingParams"):
    logger.info("Get forward rules for all users.")
    users = get_all_api360_users(settings)
    if not users:
        logger.info("No users found in Y360 organization.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return

    rules = []
    forward_dict = {}
    autoreply_dict = {}
    count = 0
    logger.info(f"Total users count - {len(users)}.")
    with console.status("[bold green]Getting forward rules for all users from API...", spinner="dots"):
        for user in users:
            if user["id"].startswith("113"):
                count += 1
                if count % 10 == 0:
                    logger.info(f"Processed {count} users (total users count - {len(users)}).")
                response_json = get_forward_rules_from_api(settings, user) 
                if response_json:   
                    if response_json["forwards"]:
                        rules = []
                        for forward in response_json["forwards"]:
                            rules.append(forward)
                        forward_dict[user["id"]] = rules
                    if response_json["autoreplies"]:
                        rules = []
                        for autoreply in response_json["autoreplies"]:
                            rules.append(autoreply)
                        autoreply_dict[user["id"]] = rules

    with open(settings.forward_rules_output_file, "w", encoding="utf-8") as f:
        f.write("uid;nickname;displayName;isEnabled;forwardRules;Autoreplays\n")
        for user in users:
            forward_rules_string = ""
            autorepaly_rules_string = ""
            if user["id"] in forward_dict.keys():
                forward_rules_string = ",".join([f"{rule['address']}|{rule['withStore']}" for rule in forward_dict[user["id"]]])
            if user["id"] in autoreply_dict.keys():
                autorepaly_rules_string = "#".join([f"{rule['text']}" for rule in autoreply_dict[user["id"]]])
            f.write(f"{user['id']};{user['nickname']};{user['name']['last']} {user['name']['first']} {user['name']['middle']};{user["isEnabled"]};{forward_rules_string};{autorepaly_rules_string}\n")
        logger.info(f"{len(users)} users downloaded to file {settings.forward_rules_output_file}")
        console.input("[dim]Press Enter to continue...[/dim]")

def mfa_download_settings(settings):
    logger.info("Get 2FA settings for all users.")
    users = get_all_api360_users(settings)
    if not users:
        logger.info("No users found in Y360 organization.")
        return

    mfa = []
    count = 0
    logger.info(f"Total users count - {len(users)}.")
    with console.status("[bold green]Getting 2FA settings for all users from API...", spinner="dots"):
        for user in users:
            user_mfa = {}
            if user["id"].startswith("113"):
                user_mfa["id"] = user["id"]
                user_mfa["nickname"] = user["nickname"]
                user_mfa["displayName"] = user["name"]["last"] + " " + user["name"]["first"] + " " + user["name"]["middle"]
                user_mfa["isEnabled"] = user["isEnabled"]
                user_mfa["isAdmin"] = user["isAdmin"]
                count += 1
                if count % 10 == 0:
                    logger.info(f"Processed {count} users (total users count - {len(users)}).")
                mfa_dict = get_2fa_settings_from_api(settings, user) 

                if mfa_dict["personal_and_phone"]:
                    user_mfa["personal2FAEnabled"] = mfa_dict["personal_and_phone"]["has2fa"]
                    user_mfa["hasSecurityPhone"] = mfa_dict["personal_and_phone"]["hasSecurityPhone"]
                else:
                    user_mfa["personal2FAEnabled"] = ""
                    user_mfa["hasSecurityPhone"] = ""

                if mfa_dict["per_user_2fa"]:
                    user_mfa["domain2FAEnabled"] = mfa_dict["per_user_2fa"]["is2faEnabled"]
                else:
                    user_mfa["domain2FAEnabled"] = ""

                if mfa_dict["domain_2fa"]:
                    user_mfa["global2FAEnabled"] = mfa_dict["domain_2fa"]["enabled"]
                    user_mfa["global2FADuration"] = mfa_dict["domain_2fa"]["duration"]
                    user_mfa["global2FAPolicy"] = mfa_dict["domain_2fa"]["scope"]
                else:
                    user_mfa["global2FAEnabled"] = ""
                    user_mfa["global2FADuration"] = ""
                    user_mfa["global2FAPolicy"] = ""

                mfa.append(user_mfa)

    with open(settings.users_2fa_output_file, "w", encoding="utf-8") as f:
        f.write("uid;nickname;displayName;isEnabled;isAdmin;domain2FAEnabled;hasSecurityPhone;personal2FAEnabled;global2FAEnabled;global2FADuration;global2FAPolicy\n")
        for user in mfa:
            f.write(f"{user['id']};{user['nickname']};{user['displayName']};{user['isEnabled']};{user['isAdmin']};{user['domain2FAEnabled']};{user['hasSecurityPhone']};{user['personal2FAEnabled']};{user['global2FAEnabled']};{user['global2FADuration']};{user['global2FAPolicy']}\n")
        logger.info(f"{len(users)} users downloaded to file {settings.users_2fa_output_file}")
        console.input("[dim]Press Enter to continue...[/dim]")

def get_2fa_settings_from_api(settings: "SettingParams", user):
    logger.debug(f"Getting 2fa settings for user {user["id"]} ({user["nickname"]})...")

    url_personal_and_phone = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{user["id"]}/2fa"
    url_enable_per_user_2fa = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{user["id"]}/domain_2fa"
    url_domain_2fa = f"{DEFAULT_360_API_URL}/security/v2/org/{settings.org_id}/domain_2fa"

    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    output = {}
    data = {}
    try:
        retries = 1
        while True:
            logger.debug(f"GET url - {url_personal_and_phone}")
            response = requests.get(url_personal_and_phone, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request for user {user["id"]}: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Getting personal and phone 2fa settings for user {user["id"]} ({user["nickname"]}) failed.")
                    break
            else:
                data = response.json()
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
    
    output["personal_and_phone"] = data

    data = {}
    try:
        retries = 1
        while True:
            logger.debug(f"GET url - {url_enable_per_user_2fa}")
            response = requests.get(url_enable_per_user_2fa, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request for user {user["id"]}: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Getting per user 2fa settings for user {user["id"]} ({user["nickname"]}) failed.")
                    break
            else:
                data = response.json()
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
    
    output["per_user_2fa"] = data

    data = {}
    try:
        retries = 1
        while True:
            logger.debug(f"GET url - {url_domain_2fa}")
            response = requests.get(url_domain_2fa, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request for user {user["id"]}: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Getting domain 2fa settings for user {user["id"]} ({user["nickname"]}) failed.")
                    break
            else:
                data = response.json()
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
    
    output["domain_2fa"] = data

    return output

def mfa_prompt_settings_for_user(settings: "SettingParams"):
    logger.info("Get 2FA settings for users.")
    while True:
        
        break_flag, double_users_flag, users_to_add = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue

        if not users_to_add:
            logger.info("No users to add. Exiting.")
            continue

        for user in users_to_add:
            mfa_show_settings_for_user(settings, user)

def mfa_show_settings_for_user(settings: "SettingParams", user: dict):
    with console.status(f"[bold green]Getting 2FA settings for user {user['nickname']}...", spinner="dots"):
        mfa_dict = get_2fa_settings_from_api(settings, user)

    # Create user info table
    user_table = Table(show_header=False, box=box.SIMPLE)
    user_table.add_column("Attribute", style="cyan")
    user_table.add_column("Value", style="green")
    
    full_name = f"{user['name']['last']} {user['name']['first']} {user['name']['middle']}"
    user_table.add_row("Name:", full_name)
    user_table.add_row("Nickname:", user['nickname'])
    user_table.add_row("User ID:", user['id'])
    user_table.add_row("Is Enabled:", "✅ Yes" if user['isEnabled'] else "❌ No")
    user_table.add_row("Is Admin:", "✅ Yes" if user['isAdmin'] else "❌ No")
    
    if 'aliases' in user and user['aliases']:
        aliases_str = ", ".join(user['aliases'])
        user_table.add_row("Aliases:", aliases_str)
    
    user_panel = Panel(
        user_table,
        title="[bold blue]User Information[/bold blue]",
        border_style="blue"
    )
    
    # Create 2FA settings table
    mfa_table = Table(show_header=False, box=box.SIMPLE)
    mfa_table.add_column("Setting", style="cyan")
    mfa_table.add_column("Status", style="green")
    
    has_phone = mfa_dict["personal_and_phone"].get("hasSecurityPhone", False)
    mfa_table.add_row("Has security phone:", "✅ Yes" if has_phone else "❌ No")
    
    domain_2fa = mfa_dict["per_user_2fa"].get("is2faEnabled", False)
    mfa_table.add_row("Domain 2FA enabled:", "✅ Yes" if domain_2fa else "❌ No")
    
    personal_2fa = mfa_dict["personal_and_phone"].get("has2fa", False)
    mfa_table.add_row("Personal 2FA enabled:", "✅ Yes" if personal_2fa else "❌ No")
    
    global_2fa = mfa_dict["domain_2fa"].get("enabled", False)
    mfa_table.add_row("Global 2FA enabled:", "✅ Yes" if global_2fa else "❌ No")
    
    duration = mfa_dict["domain_2fa"].get("duration", "Unknown")
    mfa_table.add_row("Global 2FA duration:", str(duration))
    
    policy = mfa_dict["domain_2fa"].get("scope", "Unknown")
    mfa_table.add_row("Global 2FA policy:", str(policy))
    
    mfa_panel = Panel(
        mfa_table,
        title="[bold green]2FA Settings[/bold green]",
        border_style="green"
    )
    
    console.print(user_panel)
    console.print(mfa_panel)
    console.input("[dim]Press Enter to continue...[/dim]")

def mfa_reset_personal_phone_prompt(settings: "SettingParams"):
    logger.info("Reset 2FA phone for users.")
    while True:
        
        break_flag, double_users_flag, users_to_add = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue

        if not users_to_add:
            logger.info("No users to add. Exiting.")
            continue

        for user in users_to_add:
            logger.info(f"Check if {user["id"]} ({user["nickname"]}) has security phone.")
            mfa = get_2fa_settings_from_api(settings, user)
            if mfa["personal_and_phone"].get("hasSecurityPhone", False):
                mfa_reset_personal_phone(settings, user)
            else:
                logger.info(f"{user["id"]} ({user["nickname"]}) has no security phone. Skipping.")
        

def mfa_reset_personal_phone(settings: "SettingParams", user: dict):
    logger.info(f"Deleting security phone for user {user["id"]} ({user["nickname"]})")
    try:
        retries = 1
        url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{user["id"]}/2fa"
        headers = {"Authorization": f"OAuth {settings.oauth_token}"}
        logger.debug(f"DELETE URL: {url}")
        while True:
            response = requests.delete(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during DELETE request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Deleting security phone for uid {user["id"]} ({user["nickname"]}) failed.")
                    break
            else:
                logger.info(f"Success - Successfully deleted security phone for uid {user["id"]} ({user["nickname"]}).")
                break
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")


def mfa_logout_single_user_prompt(settings: "SettingParams"):
    logger.info("Logout users from Yandex 360 services.")
    while True:
        
        break_flag, double_users_flag, users_to_add = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue

        if not users_to_add:
            logger.info("No users to add. Exiting.")
            continue

        if len(users_to_add) == 1:
            if not Confirm.ask(f"[bold yellow]Do you want to logout {users_to_add[0]['id']} ({users_to_add[0]['nickname']}) from Yandex 360 services?[/bold yellow]"):
                continue
        else:
            if not Confirm.ask(f"[bold yellow]Do you want to logout {len(users_to_add)} users from Yandex 360 services?[/bold yellow]"):
                continue

        for user in users_to_add:
            mfa_logout_single_user(settings, user)

def mfa_logout_single_user(settings: "SettingParams", user: dict):
    logger.info(f"Logout user {user["id"]} ({user["nickname"]}) from Yandex 360 services.")
    try:
        retries = 1
        url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/domain_sessions/users/{user["id"]}/logout"
        headers = {"Authorization": f"OAuth {settings.oauth_token}"}
        logger.debug(f"PUT URL: {url}")
        while True:
            response = requests.put(url, headers=headers)
            logger.debug(f"x-request-id: {response.headers.get("x-request-id","")}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during PUT request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Error. Logout user {user["id"]} ({user["nickname"]}) failed.")
                    break
            else:
                logger.info(f"Success - Successfully logout user uid {user["id"]} ({user["nickname"]}).")
                break
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")

def mfa_logout_users_from_file(settings: "SettingParams"):
    logger.info(f"Logout users from Yandex 360 services from file {settings.users_2fa_input_file}.")
    all_users = []
    exit_flag = False
    double_users_flag = False

    try:
        with open(settings.users_2fa_input_file, "r", encoding="utf-8") as f:
            all_users = f.readlines()
    except FileNotFoundError:
        logger.error(f"Input file {settings.users_2fa_input_file} not found. Exiting.")
        exit_flag = True
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        exit_flag = True

    if all_users == []:
        logger.error(f"Input file {settings.users_2fa_input_file} is empty. Exiting.")
        exit_flag = True

    if exit_flag:
        return
    
    pattern = r'[;,\s]+'
    users_to_add = []
    users = get_all_api360_users(settings)
    if not users:
        logger.info("No users found in Y360 organization.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return

    for line in all_users:
        searched = re.split(pattern, line)[0].strip().lower()
        if searched in ["id", "nickname", "displayname"]:
            continue
        if "@" in searched.strip():
            searched = searched.split("@")[0]
        found_flag = False
        if all(char.isdigit() for char in searched.strip()):
            if len(searched.strip()) == 16 and searched.strip().startswith("113"):
                for user in users:
                    if user["id"] == searched.strip():
                        logger.debug(f"User found: {user['nickname']} ({user['id']})")
                        users_to_add.append(user)
                        found_flag = True
                        break
        else:
            found_last_name_user = []
            for user in users:
                aliases_lower_case = [r.lower() for r in user["aliases"]]
                if user["nickname"].lower() == searched.lower().strip() or searched.lower().strip() in aliases_lower_case:
                    logger.debug(f"User found: {user['nickname']} ({user['id']})")
                    users_to_add.append(user)
                    found_flag = True
                    break
                if user["name"]["last"].lower() == searched.lower().strip():
                    found_last_name_user.append(user)
            if not found_flag and found_last_name_user:
                if len(found_last_name_user) == 1:
                    logger.debug(f"User found ({searched}): {found_last_name_user[0]['nickname']} ({found_last_name_user[0]['id']}, {found_last_name_user[0]['position']})")
                    users_to_add.append(found_last_name_user[0])
                    found_flag = True
                else:
                    logger.error(f"User {searched} found more than one user:")
                    for user in found_last_name_user:
                        logger.error(f" - last name {user['name']['last']}, nickname {user['nickname']} ({user['id']}, {user['position']})")
                    logger.error("Refine your search parameters.")
                    double_users_flag = True
                    break

        if not found_flag:
            logger.error(f"User {searched} not found in Y360 organization.")

    if len(users_to_add) == 0:
        logger.error("No users from file {settings.users_2fa_input_file} found in Y360 organization.")
        console.input("[dim]Press Enter to continue...[/dim]")
        return

    if len(users_to_add) == 1:
            answer = input("Do you want to logout {user['id'] (user['nickname]) from Yandex 360 services? (yes/n): ")
    else:
        logger.info(f"Some users from file {settings.users_2fa_input_file} found in Y360 organization:")
        if len(users_to_add) <= 3:
            for user in users_to_add:
                logger.info(f" - nickname - {user['nickname']}, id - {user['id']}, name - {user['name']['last']} {user['name']['first']} {users_to_add[0]['name']['middle']}")
        else:
            middle_index = len(users_to_add) // 2
            logger.info(f" - nickname - {users_to_add[0]['nickname']}, id - {users_to_add[0]['id']}, name - {users_to_add[0]['name']['last']} {users_to_add[0]['name']['first']} {users_to_add[0]['name']['middle']}")
            logger.info(" - ...")
            logger.info(f" - nickname - {users_to_add[middle_index]['nickname']}, id - {users_to_add[middle_index]['id']}, name - {users_to_add[middle_index]['name']['last']} {users_to_add[middle_index]['name']['first']} {users_to_add[middle_index]['name']['middle']}")
            logger.info(" - ...")
            logger.info(f" - nickname - {users_to_add[-1]['nickname']}, id - {users_to_add[-1]['id']}, name - {users_to_add[-1]['name']['last']} {users_to_add[-1]['name']['first']} {users_to_add[-1]['name']['middle']}")

    if len(users_to_add) == 1:
        if not Confirm.ask(f"[bold yellow]Do you want to logout {users_to_add[0]['id']} ({users_to_add[0]['nickname']}) from Yandex 360 services?[/bold yellow]"):
            return
    else:
        if not Confirm.ask(f"[bold yellow]Do you want to logout {len(users_to_add)} users from Yandex 360 services?[/bold yellow]"):
            return

    for user in users_to_add:
        mfa_logout_single_user(settings, user)

    console.input("[dim]Press Enter to continue...[/dim]")
    return

def mfa_logout_users_with_no_phone(settings: "SettingParams"):
    logger.info("Logout users with 2FA set and no security phone configured from Yandex 360 services.")
    logger.info("Get 2FA settings for all users.")
    users = get_all_api360_users(settings)
    if not users:
        logger.info("No users found in Y360 organization.")
        return

    need_logout = []
    count = 0
    logger.info(f"Total users count - {len(users)}.")
    with console.status("[bold green]Getting 2FA settings for all users from API...", spinner="dots"):
        for user in users:
            full_name = f"{user['name']['last']} {user['name']['first']} {user['name']['middle']}"
            if user["id"].startswith("113"):
                count += 1
                if count % 10 == 0:
                    logger.info(f"Processed {count} users (total users count - {len(users)}).")
                mfa_dict = get_2fa_settings_from_api(settings, user) 

                if mfa_dict is None:
                    logger.error(f"Error getting 2FA settings for user {user['nickname']} ({user['id']}).")
                    continue
                
                if mfa_dict["per_user_2fa"]:
                    if mfa_dict["per_user_2fa"]["is2faEnabled"]:
                        if mfa_dict["personal_and_phone"]:
                            if not mfa_dict["personal_and_phone"]["hasSecurityPhone"]:
                                if user["isEnabled"]:
                                    need_logout.append(user)
                                else:
                                    logger.info(f"User disabled, skipping. ({user["nickname"]}, id - {user["id"]}, full name - {full_name}).")

    if not need_logout:
        logger.info("No users found to logout (with 2FA set and no security phone added).")
        console.input("[dim]Press Enter to continue...[/dim]")
        return
    
    if len(need_logout) == 1:
            full_name = f"{need_logout[0]['name']['last']} {need_logout[0]['name']['first']} {need_logout[0]['name']['middle']}"
            answer = input(f"Do you want to logout {need_logout[0]['id']} ({need_logout[0]['nickname']}, {full_name}) from Yandex 360 services? (yes/n): ")
    else:
        logger.info("Enabled users with 2FA set and no security phone added:")
        if len(need_logout) <= 3:
            for user in need_logout:
                logger.info(f" - nickname - {user['nickname']}, id - {user['id']}, name - {user['name']['last']} {user['name']['first']} {need_logout[0]['name']['middle']}")
        else:
            for user in need_logout:
                logger.debug(f" - nickname - {user['nickname']}, id - {user['id']}, name - {user['name']['last']} {user['name']['first']} {need_logout[0]['name']['middle']}")

            middle_index = len(need_logout) // 2
            logger.info(f" - nickname - {need_logout[0]['nickname']}, id - {need_logout[0]['id']}, name - {need_logout[0]['name']['last']} {need_logout[0]['name']['first']} {need_logout[0]['name']['middle']}")
            logger.info(" - ...")
            logger.info(f" - nickname - {need_logout[middle_index]['nickname']}, id - {need_logout[middle_index]['id']}, name - {need_logout[middle_index]['name']['last']} {need_logout[middle_index]['name']['first']} {need_logout[middle_index]['name']['middle']}")
            logger.info(" - ...")
            logger.info(f" - nickname - {need_logout[-1]['nickname']}, id - {need_logout[-1]['id']}, name - {need_logout[-1]['name']['last']} {need_logout[-1]['name']['first']} {need_logout[-1]['name']['middle']}")
            if not Confirm.ask(f"[bold yellow]Do you want to logout {len(need_logout)} users from Yandex 360 services?[/bold yellow]"):
                return

    # This condition is now handled above, but keeping for single user case
    if len(need_logout) == 1:
        full_name = f"{need_logout[0]['name']['last']} {need_logout[0]['name']['first']} {need_logout[0]['name']['middle']}"
        if not Confirm.ask(f"[bold yellow]Do you want to logout {need_logout[0]['id']} ({need_logout[0]['nickname']}, {full_name}) from Yandex 360 services?[/bold yellow]"):
            return

    for user in need_logout:
        mfa_logout_single_user(settings, user)

    console.input("[dim]Press Enter to continue...[/dim]")


if __name__ == "__main__":
    # Display startup banner
    console.print(Panel(
        Text.assemble(
            ("🚀 ", "bold blue"),
            ("Yandex 360 Text Admin Console", "bold green"),
            (" 🚀\n", "bold blue"),
            ("Version 2.0 with Rich UI", "cyan"),
        ),
        title="[bold yellow]Welcome[/bold yellow]",
        border_style="green",
        padding=(1, 2)
    ))

    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        with console.status("[bold green]Loading configuration...", spinner="dots"):
            load_dotenv(dotenv_path=denv_path, verbose=True, override=True)

    logger.debug("\n")
    logger.debug("---------------------------------------------------------------------------.")
    logger.debug("Запуск скрипта.")

    with console.status("[bold green]Initializing settings...", spinner="dots"):
        settings = get_settings()
    
    if settings is None:
        console.print("[bold red]❌ Check config setting in .env file and try again.[/bold red]")
        sys.exit(EXIT_CODE)

    # Display configuration info
    config_table = Table(title="Configuration Parameters")
    config_table.add_column("Parameter", style="cyan")
    config_table.add_column("Value", style="green")
    config_table.add_row("ORG_ID", str(settings.org_id))
    config_table.add_row("SCIM_DOMAIN_ID", str(settings.domain_id))
    config_table.add_row("Ignore Username Domain", str(settings.ignore_user_domain))
    config_table.add_row("SCIM API Available", "❌ No" if settings.skip_scim_api_call else "✅ Yes")
    
    console.print(config_table)

    try:
        main(settings)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]👋 Ctrl+C pressed. Goodbye![/bold yellow]")
        sys.exit(EXIT_CODE)
    except Exception as e:
        console.print(f"[bold red]❌ {type(e).__name__} at line {e.__traceback__.tb_lineno}: {e}[/bold red]")
        sys.exit(EXIT_CODE)