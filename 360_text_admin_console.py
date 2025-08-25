from datetime import date, datetime
from enum import auto
from operator import ge
from unittest import result
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
from os import environ
import argparse
import csv
import re

DEFAULT_360_SCIM_API_URL = "https://{domain_id}.scim-api.passport.yandex.net/"
DEFAULT_360_API_URL = "https://api360.yandex.net"
DEFAULT_360_API_URL_V2 = "https://cloud-api.yandex.net/v1/admin/org"
ITEMS_PER_PAGE = 100
MAX_RETRIES = 3
LOG_FILE = "360_text_admin_console.log"
RETRIES_DELAY_SEC = 2
SLEEP_TIME_BETWEEN_API_CALLS = 0.5
ALL_USERS_REFRESH_IN_MINUTES = 15

EXIT_CODE = 1

logger = logging.getLogger("change_scim_user_name")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
#file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30, encoding='utf-8')
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
        skip_scim_api_call = False,
        target_group = {},
        all_users = [],
        all_users_get_timestamp = datetime.now()
    )

    if not settings.scim_token:
        logger.info("SCIM_TOKEN_ARG is not set")
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
    
    if not settings.oauth_token:
        logger.info("OAUTH_TOKEN_ARG is not set")
        oauth_token_bad = True

    if not settings.org_id:
        logger.error("ORG_ID_ARG is not set")
        exit_flag = True

    if not (scim_token_bad or exit_flag):
        if not check_scim_token(settings.scim_token, settings.domain_id):
            logger.info("SCIM_TOKEN_ARG is not valid")
            scim_token_bad = True

    if not (oauth_token_bad or exit_flag):
        if not check_oauth_token(settings.oauth_token, settings.org_id):
            logger.info("OAUTH_TOKEN_ARG is not valid")
            oauth_token_bad = True

    if scim_token_bad:
        settings.skip_scim_api_call = True

    if oauth_token_bad:
        exit_flag = True
    
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

    value = input("Enter old and new value of userName, separated by space: ").strip()
    if not value:
        logger.error("String can not be empty.")
        return
    
    if len(value.split()) != 2:
        logger.error("There must be exactly two arguments.")
        return
    
    old_value, new_value = value.split()
    single_mode(settings, old_value, new_value)

def single_mode(settings: "SettingParams", old_value, new_value):
    users  = get_all_scim_users(settings)
    if users:
        old_user = next((item for item in users if item["userName"] == old_value.lower()), None)
        if not old_user:
            logger.error(f"User {old_value} not found.")
            return
        new_user= next((item for item in users if item["userName"] == new_value.lower()), None)
        if new_user:
            logger.error(f"User {old_value} already exist in system. Select another new value for userName.")
            return
        logger.info(f"User {old_value} found. UID: {old_user['id']}. Start changing userName to {new_value}...")
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
                
                response = requests.patch(f"{url}/v2/Users/{uid}", headers=headers, json=data)
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
                    logger.info(f"Success - User {old_value} changed to {new_value}.")
                    break

        except Exception as e:
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
    else:
        logger.debug("List of users is empty.")

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
                logger.info("Need confirmation.")
                answer = input("Need confirmation (yes/no): ").strip().lower()
                while answer not in ["yes", "no"]:
                    logger.warning("Enter 'yes' или 'no'")
                    answer = input("Need confirmation (yes/no): ").strip().lower()
                if answer == "yes":
                    if attribute.lower() == "username":
                        single_mode(settings, old_value, new_value)
                    elif attribute.lower() == "nickname":
                        change_nickname(settings, old_value, new_value)
                else:
                    logger.info("Execution canceled.")
                    sys.exit(0)

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        sys.exit(1)

def main_menu(settings: "SettingParams"):

    while True:
        print("\n")
        print("Select option:")
        print("1. Work with SCIM userName attribute or with API 360 nickname attribute.")
        print("2. Get user info.")
        print("3. Get group info and manage send permission.")
        print("4. Work with email settings.")

        print("0. Exit")
        choice = input("Enter your choice (0-4) or Ctrl+C: ")

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            submenu_1(settings)
        elif choice == "2":
            submenu_2(settings)
        elif choice == "3":
            submenu_3(settings)
        elif choice == "4":
            submenu_4(settings)
        else:
            print("Invalid choice. Please try again.")



def submenu_1(settings: "SettingParams"):
    while True:
        print("\n")
        print("=== Work with SCIM userName attribute or with API 360 nickname attribute ===")
        print("------------------------------ Config params -------------------------------")
        print(f'New loginName format: {settings.new_login_default_format}')
        print("----------------------------------------------------------------------------")
        print("\n")
        print("Select option:")
        print("1. Set new SCIM userName format (default: alias@domail.tld).")
        print("2. Create SCIM data file for modification in next step.")
        print("3. Use users file to change SCIM userName of users.")
        print("4. Enter old and new value of userName manually and confirm renaming.")
        print("5. Change nickname of single user.")
        print("0. Back to main menu.")

        choice = input("Enter your choice (0-5) or Ctrl+C to exit script: ")

        if choice == "0":
            break
        elif choice == "1":
            print('\n')
            set_new_loginName_format(settings)
        elif choice == "2":
            if settings.skip_scim_api_call:
                logger.info("No SCIM config found. Skip action.")
            else:
                print('\n')
                create_SCIM_userName_file(settings)
        elif choice == "3":
            if settings.skip_scim_api_call:
                logger.info("No SCIM config found. Skip action.")
            else:
                print('\n')
                update_users_from_SCIM_userName_file(settings)
        elif choice == "4":
            if settings.skip_scim_api_call:
                logger.info("No SCIM config found. Skip action.")
            else:
                print('\n')
                change_SCIM_username_manually(settings)
        elif choice == "5":
            print('\n')
            change_nickname_prompt(settings)
        else:
            print("Invalid choice. Please try again.")
    return

def submenu_2(settings: "SettingParams"):
    while True:
        print("\n")
        print("============================== Get user info ===============================")
        #print("\n")
        print("Select option:")
        print("1. Check alias for user.")
        print("2. Download all users to file (SCIM и API) protocols.")
        print("3. Show user attributes and save their to file.")
        print("0. Back to main menu.")

        choice = input("Enter your choice (0-3) or Ctrl+C to exit script: ")

        if choice == "0":
            break
        elif choice == "1":
            print('\n')
            check_alias_prompt(settings)
        elif choice == "2":
            print('\n')
            download_users_attrib_to_file(settings)
        elif choice == "3":
            print('\n')
            show_user_attributes(settings)
        else:
            print("Invalid choice. Please try again.")

    return

def submenu_3(settings: "SettingParams"):
    while True:
        print("\n")
        print("============================== Get group info ===============================")
        #print("\n")
        print("Select option:")
        print("1. Show group attributes and save their to file.")
        print("2. Show approve senders for group.")
        print("3. Manage approve senders for group.")
        print("0. Back to main menu.")

        choice = input("Enter your choice (0-3) or Ctrl+C to exit script: ")

        if choice == "0":
            break
        elif choice == "1":
            print('\n')
            save_group_data_prompt(settings)
        elif choice == "2":
            print('\n')
            show_mailing_list_permissions(settings)
        elif choice == "3":
            subsubmenu_30(settings)
        else:
            print("Invalid choice. Please try again.")

    return


def submenu_4(settings: "SettingParams"):
    while True:
        print("\n")
        print("====================== Work with email settings =============================")
        #print("\n")
        print("Select option:")
        print("1. Create file for default email modification.")
        print("2. Update default email from file.")
        print("3. Get forward rules for single user.")
        print("4. Download forward rules for all users.")
        print("5. Clear forward rules for users.")
        print("0. Back to main menu.")

        choice = input("Enter your choice (0-5) or Ctrl+C to exit script: ")

        if choice == "0":
            break
        elif choice == "1":
            print('\n')
            default_email_create_file(settings)
        elif choice == "2":
            print('\n')
            default_email_update_from_file(settings)
        elif choice == "3":
            print('\n')
            forward_rules_get_for_user(settings)
        elif choice == "4":
            print('\n')
            forward_rules_dowanload_for_all_users(settings)
        elif choice== "5":
            print('\n')
            forward_rules_clear_for_user(settings)
        else:
            print("Invalid choice. Please try again.")

    return

def subsubmenu_30(settings: "SettingParams"):
    while True:
        print("\n")
        print("====================== Manage group send permissions =============================")
        print("------------------------------ Current params -------------------------------")
        print(f'Target group Name - {settings.target_group.get("name","")}')
        print(f'Target group ID - {settings.target_group.get("id","")}')
        print(f'Target group emailId - {settings.target_group.get("emailId","")}')
        print("----------------------------------------------------------------------------")
        #print("\n")
        print("Select option:")
        print("1. Set target group.")
        print("2. Add users to allow list.")
        print("3. Remove users from allow list.")
        print("4. Grand all users send permission.")
        print("0. Back to main menu.")

        choice = input("Enter your choice (0-4) or Ctrl+C to exit script: ")

        if choice == "0":
            break
        elif choice == "1":
            print('\n')
            send_perm_set_target_group(settings)
        elif choice == "2":
            print('\n')
            send_perm_add_users_to_allow_list_prompt(settings)
        elif choice == "3":
            print('\n')
            send_perm_remove_users_from_allow_list(settings)
        elif choice == "4":
            print('\n')
            send_perm_grand_all_users(settings)
        else:
            print("Invalid choice. Please try again.")

    return

def set_new_loginName_format(settings: "SettingParams"):
    answer = input("Enter format of new userLogin name (space to use default format alias@domain.tld):\n")
    if answer:
        if answer.strip() == "":
            settings.new_login_default_format = "alias@domain.tld"
        else:
            settings.new_login_default_format = answer.strip()

    return settings

def get_all_api360_users(settings: "SettingParams", force = False):
    if not force:
        logger.info("Getting all users of the organisation from cache...")

    if not settings.all_users or force:
        logger.info("Getting all users of the organisation from API...")
        settings.all_users = get_all_api360_users_from_api(settings)
        settings.all_users_get_timestamp = datetime.now()
    else:
        if (datetime.now() - settings.all_users_get_timestamp).total_seconds() > ALL_USERS_REFRESH_IN_MINUTES * 60:
            logger.info("Getting all users of the organisation from API...")
            settings.all_users = get_all_api360_users_from_api(settings)
            settings.all_users_get_timestamp = datetime.now()
    return settings.all_users

def get_all_api360_users_from_api(settings: "SettingParams"):
    logger.info("Getting all users of the organisation...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users?perPage=100"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    try:
        response = requests.get(url, headers=headers)
        if response.ok:
                users = response.json()['users']
                for i in range(2, response.json()["pages"] + 1):
                    logger.info(f"Getting users from API, page {i} of {response.json()['pages']} (one page = 100 users)")
                    response = requests.get(f"{url}&page={i}", headers=headers)
                    if response.ok:
                        users.extend(response.json()['users'])

    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
    return users

def get_all_groups(settings: "SettingParams"):
    logger.info("Getting all groups of the organisation...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/groups?perPage=100"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    groups = []
    try:
        page = 1
        while True:
            response = requests.get(f"{url}&page={page}", headers=headers)
            if response.ok:
                data = response.json()
                groups.extend(data['groups'])
                if page >= data.get("pages", 1):
                    break
                page += 1
            else:
                logger.error(f"Error during GET request: {response.status_code}. Error message: {response.text}")
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
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
            response = requests.get(url, headers=headers)
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
            response = requests.get(f"{url}/v2/Users?startIndex={startIndex}&count={items}", headers=headers)
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
    
    return users

def change_nickname_prompt(settings: "SettingParams"):
    while True:
        data = input("Enter old value and new value of nickname separated by space (empty sting to exit): ")
        if len(data.strip()) == 0:
            break
        elif len(data.split()) != 2:
            logger.error("Invalid input. Please enter old value and new value separated by space.")
        else:
            old_value, new_value = data.split()
            change_nickname(settings, old_value, new_value)
    return

def check_alias_prompt(settings: "SettingParams"):
    while True:
        data = input("Enter alias (without domain) to check (empty sting to exit): ")
        if len(data.strip()) == 0:
            break
        elif len(data.split("@")) == 2:
            data=data.split("@")[0]

        check_alias(settings, data.lower())
    return

def check_alias(settings: "SettingParams", alias: str):
    logger.info(f"Checking alias {alias}")
    users = get_all_api360_users(settings)
    if not users:
        logger.error("No users found.")
    logger.info(f"{len(users)} users found.")
    
    for user in users:
        if alias == user['nickname']:
            logger.info(f"Alias _ {alias} _ already exists as nickname in user with nickname {user['nickname']}. User ID - {user['id']}.  User displayName - {user.get('displayName','')}.")
        if alias in user['aliases']:
            logger.info(f"Alias _ {alias} _ already exists as alias in user with nickname {user['nickname']}. User ID - {user['id']}.  User displayName - {user.get('displayName','')}.")
        for contact in user['contacts']:
            if contact['type'] == 'email' and contact['value'].split('@')[0] == alias:
                logger.info(f"Alias _ {alias} _ already exists as email contact in user with nickname {user['nickname']}. User ID - {user['id']}. User displayName - {user.get('displayName','')}.")

    scim_users = get_all_scim_users(settings)
    if not scim_users:
        logger.error("No users found.")
    for user in scim_users:
        if alias == user['userName'] or alias == user['userName'].split('@')[0]:
            logger.info(f"Alias _ {alias} _ already exists as userName in _SCIM_ user with ID - {user['id']}.  User displayName - {user['displayName']}.")

def change_nickname(settings: "SettingParams", old_value: str, new_value: str):
    logger.info(f"Changing nickname of user {old_value} to {new_value}")
    users = get_all_api360_users(settings)
    
    if not users:
        logger.error("No users found.")
        return
    logger.info(f"{len(users)} users found.")

    target_user = [user for user in users if user['nickname'] == old_value]
    if not target_user:
        logger.error(f"User with nickname {old_value} not found.")
        return
    logger.info(f"User with nickname {old_value} found. User ID - {target_user[0]['id']}")

    existing_user = [user for user in users if user['nickname'] == new_value]
    if existing_user:
        logger.error(f"User with nickname {new_value} already exists. User ID - {existing_user[0]['id']}. Clear this nickname and try again.")
        return
    
    for user in users:
        if new_value in user['aliases'] and user['nickname'] != old_value:
            logger.error(f"Nickname {new_value} already exists as alias in user with nickname {user['nickname']}. User ID - {user['id']}. Clear this alias in this user and try again.")
            return
        if user['nickname'] != old_value:
            for contact in user['contacts']:
                if contact['type'] == 'email' and contact['value'].split('@')[0] == new_value:
                    logger.error(f"Nickname {new_value} already exists as email contact in user with nickname {user['nickname']}. User ID - {user['id']}. Clear this contact email in this user and try again.")
                    return
    
    if new_value in target_user[0]['aliases']:
        remove_alias_in_scim(target_user[0]["id"], new_value)

    for contact in target_user[0]['contacts']:
        if contact['type'] == 'email' and contact['value'].split('@')[0] == new_value:
            remove_email_in_scim(target_user[0]["id"], new_value)

    logger.info(f"Changing nickname of user {old_value} to {new_value}")
    raw_data = {'nickname': new_value}
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users/{target_user[0]['id']}"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    try:
        response = requests.patch(url, headers=headers, data=json.dumps(raw_data))
        if response.ok:
            logger.info(f"Nickname of user {old_value} changed to {new_value}")
            time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)
        else:
            logger.error(f"Error ({response.status_code}) changing nickname of user {old_value} to {new_value}: {response.text}")
            return

    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return 
    
    remove_alias_in_scim(target_user[0]["id"], old_value)
    remove_email_in_scim(target_user[0]["id"], old_value)

def remove_alias_in_scim(user_id: str, alias: str):
    logger.info(f"Check if exist and removing alias {alias} in _SCIM_ user {user_id}")

    url = DEFAULT_360_SCIM_API_URL.format(domain_id=settings.domain_id)
    headers = {"Authorization": f"Bearer {settings.scim_token}"}
    try:
        response = requests.get(f"{url}/v2/Users/{user_id}", headers=headers)
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

                    response = requests.patch(f"{url}/v2/Users/{user_id}", headers=headers, data=json.dumps(data))
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
        response = requests.get(f"{url}/v2/Users/{user_id}", headers=headers)
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

                response = requests.patch(f"{url}/v2/Users/{user_id}", headers=headers, data=json.dumps(data))
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
        logger.info("No users found. Check your settings.")
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
        return
    else:
        for user in user_for_change:
            logger.debug(f"Will modify - {temp}.")

        answer = input(f"Modify userName SCIM attribute for {len(user_for_change)} users? (Y/n): ")
        if answer.upper() not in ["Y", "YES"]:
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
                
                response = requests.patch(f"{url}/v2/Users/{uid}", headers=headers, json=data)
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
    while True:
        answer = input("Enter target user key in format: id:<UID> or userName:<SCIM_USER_NAME> or <API_360_NICKNAME> or <API_360_ALIAS> (empty string to exit): ")
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
                    if user["nickname"] == value or value in user["aliases"]:
                        target_user = user
                        break
        elif key.lower() == "username":
            for user in scim_users:
                if user["userName"] == value:
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
        
        logger.info("\n")
        logger.info("--------------------------------------------------------")
        logger.info(f'API 360 attributes for user with id: {target_user["id"]}')
        logger.info("--------------------------------------------------------")
        for k, v in target_user.items():
            if k.lower() == "contacts":
                logger.info("Contacts")
                for l in v: 
                    for k1, v1 in l.items():  
                        logger.info(f" - {k1}: {v1}")
                    logger.info(" -")
            elif k.lower() == "aliases":
                logger.info("Aliases")
                for l in v:
                    logger.info(f" - {l}")
            elif k.lower() == "name":
                logger.info("Name")
                for k1, v1 in v.items():  
                    logger.info(f" - {k1}: {v1}")
            else:
                logger.info(f"{k}: {v}")
        logger.info("--------------------------------------------------------")
        if not settings.skip_scim_api_call:
            logger.info("--------------------------------------------------------")
            logger.info(f'SCIM attributes for user with id: {target_scim_user["id"]}')
            logger.info("--------------------------------------------------------")
            for k, v in target_scim_user.items():
                if k.lower() == "emails":
                    logger.info("Emails")
                    for l in v:
                        for k1, v1 in l.items():   
                            logger.info(f" - {k1}: {v1}")
                        logger.info(" -")
                elif k.lower() == "metadata":
                    logger.info("Metadata")
                    for k1, v1 in v.items():  
                        logger.info(f" - {k1}: {v1}")
                elif k.lower() == "name":
                    logger.info("name")
                    for k1, v1 in v.items():  
                        logger.info(f" - {k1}: {v1}")
                elif k.lower() == "meta":
                    logger.info("meta")
                    for k1, v1 in v.items():  
                        logger.info(f" - {k1}: {v1}")
                elif k.lower() == "phonenumbers":
                    logger.info("phoneNumbers")
                    for l in v:
                        for k1, v1 in l.items():  
                            logger.info(f" - {k1}: {v1}")
                        logger.info(" -")
                elif k == "urn:ietf:params:scim:schemas:extension:yandex360:2.0:User":
                    logger.info("aliases")
                    for l in v["aliases"]:
                        for k1, v1 in l.items():
                            logger.info(f" - {k1}: {v1}")
                else:
                    logger.info(f"{k}: {v}")
            logger.info("--------------------------------------------------------")

        logger.info("\n")
        with open(f"{target_user['nickname']}.txt", "w", encoding="utf-8") as f:
            f.write(f'API 360 attributes for user with id: {target_user["id"]}\n')
            f.write("--------------------------------------------------------\n")
            for k, v in target_user.items():
                if k.lower() == "contacts":
                    f.write("Contacts\n")
                    for l in v: 
                        for k1, v1 in l.items():  
                            f.write(f" - {k1}: {v1}\n")
                        f.write(" -\n")
                elif k.lower() == "aliases":
                    f.write("Aliases\n")
                    for l in v:
                        f.write(f" - {l}\n")
                elif k.lower() == "name":
                    f.write("Name\n")
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
                        f.write("Emails\n")
                        for l in v:
                            for k1, v1 in l.items():   
                                f.write(f" - {k1}: {v1}\n")
                            f.write(" -\n")
                    elif k.lower() == "metadata":
                        f.write("Metadata\n")
                        for k1, v1 in v.items():  
                            f.write(f" - {k1}: {v1}\n")
                    elif k.lower() == "name":
                        f.write("name\n")
                        for k1, v1 in v.items():  
                            f.write(f" - {k1}: {v1}\n")
                    elif k.lower() == "meta":
                        f.write("meta\n")
                        for k1, v1 in v.items():  
                            f.write(f" - {k1}: {v1}\n")
                    elif k.lower() == "phonenumbers":
                        f.write("phoneNumbers\n")
                        for l in v:
                            for k1, v1 in l.items():  
                                f.write(f" - {k1}: {v1}\n")
                            f.write(" -\n")
                    elif k == "urn:ietf:params:scim:schemas:extension:yandex360:2.0:User":
                        f.write("aliases")
                        for l in v["aliases"]:
                            for k1, v1 in l.items():
                                f.write(f" - {k1}: {v1}\n")
                    else:
                        f.write(f"{k}: {v}\n")
                f.write("--------------------------------------------------------\n")
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

    while True:
        
        answer = input("Enter group alias, id or uid to get mailing list permissions (empty string to exit): ")
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
        
        # Display group attributes in console
        logger.info("\n")
        logger.info("--------------------------------------------------------")
        logger.info(f'Group attributes for group with id: {target_group["id"]}')
        logger.info("--------------------------------------------------------")
        
        for k, v in target_group.items():
            if k.lower() == "aliases":
                logger.info("Aliases:")
                for alias_item in v:
                    logger.info(f" - {alias_item}")
            elif k.lower() == "members":
                logger.info("Members:")
                for member in v:
                    member_id = member.get('id', '')
                    member_type = member.get('type', '')
                    if member_type == 'group':
                        group_name = group_id_to_name.get(str(member_id), 'Unknown')
                        logger.info(f" - type: {member_type}, id: {member_id} ({group_name})")
                    else:
                        nickname = user_id_to_nickname.get(member_id, 'Unknown')
                        logger.info(f" - type: {member_type}, id: {member_id} ({nickname})")
            elif k.lower() == "memberof":
                logger.info("Member of:")
                for member_of in v:
                    # member_of should be a group ID, find the group name
                    group_name = group_id_to_name.get(str(member_of), 'Unknown')
                    logger.info(f" - {member_of} ({group_name})")
            else:
                logger.info(f"{k}: {v}")
        
        logger.info("--------------------------------------------------------")
        logger.info("\n")
        
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
        
        logger.info(f"Group attributes saved to file: {filename}")
    return

def show_mailing_list_permissions(settings: "SettingParams", input_group = {}):
    users = []
    user_id_to_nickname = {}
    while True:
        if not input_group:
            answer = input("Enter group alias, id or uid to get mailing list permissions (empty string to exit): ")
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
        
        # Get mailing list permissions
        permissions = get_mailing_list_permissions(settings, target_group['emailId'])
        if permissions is None:
            logger.error(f"Failed to get mailing list permissions for group {target_group['name']}")
            continue
        
        # Display results in the specified format
        group_name = target_group.get('name', 'Unknown')
        group_id = target_group['id']
        group_email = target_group.get('email', 'Unknown')
        
        logger.info("\n")
        logger.info("--------------------------------------------------------")
        logger.info(f'Group attributes for group with id: {target_group["id"]}')
        logger.info("--------------------------------------------------------")
        logger.info(f"name: {group_name}")
        logger.info(f"id: {group_id}")
        logger.info(f"email: {group_email}")
        logger.info(f"emailId: {target_group.get('emailId', 'Unknown')}")
        logger.info("Approved senders:")
        
        # Display subjects from API response
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
                            logger.info(f" - type: {subject_type}, id: {subject_id} (nickname: {nickname})")
                    elif subject_type == 'anonymous':
                        logger.info(f" - type: {subject_type}")
                    elif subject_type == 'organization':
                        logger.info(f" - type: {subject_type}, org_id: {subject.get('org_id', '')}")
                    else:
                        logger.info(f" - type: {subject_type}, org_id: {subject.get('org_id', '')}, id: {subject.get('id', '')}")
        if count_senders == 0:
            logger.info(" - No permission subjects found.")
            logger.info("--------------------------------------------------------")
            logger.info("!!! WARNING !!! - NOBODY can send mail to this group.")
        logger.info("--------------------------------------------------------")
        logger.info("\n")

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
            response = requests.get(url, headers=headers)
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
                logger.debug(f"Raw JSON -  {json.dumps(data)}")
                return data
    except requests.exceptions.RequestException as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return None

def download_users_attrib_to_file(settings: "SettingParams"):
    users = get_all_api360_users(settings, force=True)
    scim_users = get_all_scim_users(settings)  
    if not users:
        logger.error("No users found from API 360 calls.")
        return
    else:
        with open('api_users.csv', 'w', encoding='utf-8', newline='') as csv_file:
            fieldnames = users[0].keys()
            writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
            writer.writeheader()
            for user in users:
                writer.writerow(user)
            logger.info(f"Saved {len(users)} API users to api_users.csv")
    if not scim_users:
        logger.error("No users found from SCIM calls.")
        return
    else:
        with open('scim_users.csv', 'w', encoding='utf-8', newline='') as csv_file:
            fieldnames = scim_users[0].keys()
            writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
            writer.writeheader()
            for user in scim_users:
                writer.writerow(user)
            logger.info(f"Saved {len(scim_users)} SCIM users to scim_users.csv")

def default_email_create_file(settings: "SettingParams"):
    users = get_all_api360_users(settings)
    if not users:
        logger.error("No users found from API 360 calls.")
        return
    else:
        email_dict = {}
        for user in users:
            if user["id"].startswith("113"):
                default_email_json = get_default_email(settings, user["id"])
                email_dict[user["id"]] = default_email_json

        with open(settings.default_email_output_file, "w", encoding="utf-8") as f:
            f.write("nickname;new_DefaultEmail;new_DisplayName;old_DefaultEmail;old_DisplayName;uid\n")
            for key in email_dict.keys():
                email_data = email_dict[key]
                if email_data:
                    f.write(f"{user['nickname']};{email_data['defaultFrom']};{email_data['fromName']};{email_data['defaultFrom']};{email_data['fromName']};{user['id']}\n")
            logger.info(f"Default emails downloaded to {settings.default_email_output_file} file.")

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
        return

    if "@" in all_users[0]:
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
        return
    
    if not normalized_users:
        logger.info("List of modified users is empty. File must contains column 'nickname' and actual data in 'new_DefaultEmail' or 'new_DisplayName' columns.")
        return
    
    answer = input(f"Modify personal email data for {len(normalized_users)} users? (Y/n): ")
    if answer.upper() not in ["Y", "YES"]:
        return
    
    api_users = get_all_api360_users(settings)
    if not api_users:
        logger.error("No users found from API 360 calls.")
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
                response = requests.post(f"{url}/{uid}/settings/sender_info", headers=headers, json=data)
                if response.status_code != HTTPStatus.OK.value:
                    logger.error(f"Error during PATCH request: {response.status_code}. Error message: {response.text}")
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

def send_perm_set_target_group(settings: "SettingParams"):
    while True:
        print("\n")
        answer = input("Enter group alias, id or uid to get mailing list permissions (empty string to exit): ")
        if not answer.strip():
            break
        
        target_group, groups = get_target_group_data_prompt(settings, answer)
        if not target_group:
            continue
        elif str(target_group["emailId"]) == "0":
            logger.error(f"Group with alias {answer} is not mail enabled. Exiting.")
            settings.target_group = {}
            continue
        else:
            logger.info(f"Target group set: {target_group['name']} ({target_group['id']}, {target_group['emailId']})")
            break
    return

def send_perm_add_users_to_allow_list_prompt(settings: "SettingParams"):
    while True:

        break_flag, double_users_flag, users_to_add = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue
        
        if not users_to_add:
            logger.info("No users to add. Exiting.")
            continue

        if send_perm_call_api(settings, users_to_add, "ADD_USER"):
            show_mailing_list_permissions(settings, settings.target_group)
            break

def send_perm_remove_users_from_allow_list(settings: "SettingParams"):
    while True:
        break_flag, double_users_flag, users_to_remove = find_users_prompt(settings)
        if break_flag:
            break
        
        if double_users_flag:
            continue
        
        if not users_to_remove:
            logger.info("No users to remove. Exiting.")
            continue

        if send_perm_call_api(settings, users_to_remove, "REMOVE_USER"):
            show_mailing_list_permissions(settings, settings.target_group)
            break
        
def send_perm_grand_all_users(settings: "SettingParams"):

    if not settings.target_group:
        logger.info("No target group set. Exiting.")
        return
    
    show_mailing_list_permissions(settings, settings.target_group)

    answer = input("Need confirmation for setting grand all permission (yes/no): ").strip().lower()
    while answer not in ["yes", "no"]:
        logger.warning("Enter 'yes' или 'no'")
        answer = input("Need confirmation for setting grand all permission (yes/no): ").strip().lower()

    if answer == "yes":
        if send_perm_call_api(settings, None, "SET_DEFAULT"):
            show_mailing_list_permissions(settings, settings.target_group)
    else:
        logger.info("Execution canceled.")

    return
def send_perm_call_api(settings: "SettingParams", users_to_change, mode):
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
            logger.error(f"Failed to get mailing list permissions for group {settings.target_group['name']}")

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

    if not data["role_actions"]:
        logger.error("No users to modify for send permissions for group {settings.target_group['name']}. Exiting.")
        return return_value
    elif not data["role_actions"][0]["subjects"]:
        logger.error("No users to modify for send permissions for group {settings.target_group['name']}. Exiting.")
        return return_value

    logger.debug(f"Raw url: {url}")
    logger.debug(f"Raw JSON: {json.dumps(data)})")
    try:
        retries = 1

        while True:
            response = requests.post(url, headers=headers, json=data)
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
    response_json = get_forward_rules_from_api(settings, user)

    logger.info("\n")
    logger.info("--------------------------------------------------------")
    logger.info(f'Forward rules for user: {user["id"]}')
    logger.info("--------------------------------------------------------")
    logger.info(f"name: {user['name']['last']} {user['name']['first']} {user['name']['middle']}")
    logger.info(f"nickname: {user['nickname']}")
    if 'aliases' in user:
        logger.info("aliases:")
        for alias in user['aliases']:
            logger.info(f" - {alias}")
    logger.info(f"position: {user['position']}")
    logger.info("Forward rules:")
    if response_json["forwards"]:   
        for forward in response_json["forwards"]:   
            logger.info(f" - address: {forward['address']}, save in mailbox: {forward['withStore']}")
    else:
        logger.info(" - No forward rules found.")
    logger.info("Autoreplies rules:")
    if response_json["autoreplies"]:   
        for autoreply in response_json["autoreplies"]:   
            logger.info(f" - text: {autoreply['text']}")
    else:
        logger.info(" - No autoreplays rules found.")
    logger.info("--------------------------------------------------------")
    logger.info("\n")

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

    answer = input("Enter users aliases or uid or last name, separated by comma or space (empty string to exit): ")
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
                if user["nickname"] == searched.lower().strip() or searched.lower().strip() in user["aliases"]:
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
            response = requests.get(url, headers=headers)
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
    logger.debug(f"URL: {url}")

    try:
        retries = 1
        while True:
            response = requests.delete(url, headers=headers)
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

def forward_rules_dowanload_for_all_users(settings: "SettingParams"):
    logger.info("Get forward rules for all users.")
    users = get_all_api360_users(settings)
    if not users:
        logger.info("No users found in Y360 organization.")
        return

    rules = []
    forward_dict = {}
    autoreply_dict = {}
    count = 0
    logger.info(f"Total users count - {len(users)}.")
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


if __name__ == "__main__":

    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)

    logger.debug("Запуск скрипта.")

    settings = get_settings()
    if settings is None:
        logger.error("Check config setting in .env file and try again.")
        sys.exit(EXIT_CODE)

    try:
        main(settings)

    except KeyboardInterrupt:
        logger.info("Ctrl+C pressed. Exiting.")
        sys.exit(EXIT_CODE)
    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        sys.exit(EXIT_CODE)